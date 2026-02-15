"""Random Forest URL/Phishing classifier engine.

Classifies URLs as benign, suspicious, or malicious using a Random Forest
model trained on 22 lexical URL features. Designed to run continuously in
parallel, checking every DNS/HTTP event with <1 ms latency per URL.

Feature extraction uses only the URL string itself (lexical analysis) --- no
network requests are made during classification. The model is trained on
labelled datasets in PhishTank / Kaggle Malicious URLs format.

Routing:
  confidence >= 0.7 malicious  -> "malicious"
  confidence >= 0.5 malicious  -> "suspicious"
  otherwise                    -> "benign"
"""

from __future__ import annotations

import logging
import math
import re
from urllib.parse import urlparse

import numpy as np
from sklearn.ensemble import RandomForestClassifier

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

MIN_TRAINING_SAMPLES = 100

FEATURE_NAMES: list[str] = [
    "url_length",
    "domain_length",
    "subdomain_depth",
    "path_depth",
    "special_char_count",
    "digit_ratio",
    "has_https",
    "has_ip_address",
    "domain_entropy",
    "tld_reputation",
    "query_param_count",
    "has_punycode",
    "brand_similarity",
    "has_at_symbol",
    "has_double_slash_redirect",
    "has_dash_in_domain",
    "path_length",
    "has_port",
    "letter_ratio",
    "dot_count",
    "has_encoded_chars",
    "suspicious_word_count",
]

TOP_BRANDS: list[str] = [
    "paypal",
    "apple",
    "google",
    "microsoft",
    "amazon",
    "facebook",
    "netflix",
    "linkedin",
    "dropbox",
    "chase",
    "wellsfargo",
    "bankofamerica",
    "citibank",
    "usbank",
]

TLD_REPUTATION: dict[str, float] = {
    ".com": 1.0,
    ".org": 0.9,
    ".net": 0.9,
    ".edu": 1.0,
    ".gov": 1.0,
    ".io": 0.7,
    ".co": 0.7,
    ".xyz": 0.3,
    ".tk": 0.1,
    ".ml": 0.1,
    ".ga": 0.1,
    ".cf": 0.1,
    ".gq": 0.1,
    ".top": 0.2,
    ".info": 0.5,
    ".biz": 0.4,
    ".ru": 0.3,
    ".cn": 0.4,
}

_TLD_DEFAULT_REPUTATION = 0.5

SUSPICIOUS_WORDS: list[str] = [
    "login",
    "verify",
    "secure",
    "account",
    "update",
    "confirm",
    "signin",
    "banking",
    "password",
    "ebayisapi",
]

# Pre-compiled patterns for performance
_IP_PATTERN = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
_ENCODED_CHAR_PATTERN = re.compile(r"%[0-9A-Fa-f]{2}")
_SPECIAL_CHARS = set("@-_~!$&'()*+,;=")


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------


def _shannon_entropy(text: str) -> float:
    """Calculate Shannon entropy of a string.

    Returns:
        Entropy in bits. Returns 0.0 for empty strings.
    """
    if not text:
        return 0.0

    length = len(text)
    freq: dict[str, int] = {}
    for ch in text:
        freq[ch] = freq.get(ch, 0) + 1

    entropy = 0.0
    for count in freq.values():
        prob = count / length
        entropy -= prob * math.log2(prob)

    return round(entropy, 4)


def _levenshtein_distance(s1: str, s2: str) -> int:
    """Compute the Levenshtein (edit) distance between two strings.

    Uses the standard dynamic-programming matrix approach with
    two-row space optimisation.

    Returns:
        Minimum number of single-character edits (insert, delete,
        substitute) to transform *s1* into *s2*.
    """
    if len(s1) < len(s2):
        return _levenshtein_distance(s2, s1)

    if not s2:
        return len(s1)

    prev_row = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        curr_row = [i + 1]
        for j, c2 in enumerate(s2):
            cost = 0 if c1 == c2 else 1
            curr_row.append(
                min(
                    curr_row[j] + 1,       # insertion
                    prev_row[j + 1] + 1,   # deletion
                    prev_row[j] + cost,     # substitution
                )
            )
        prev_row = curr_row

    return prev_row[-1]


def _extract_domain(url: str) -> str:
    """Extract the domain (hostname) from a URL string.

    Handles URLs with and without a scheme. Returns an empty string
    if no hostname can be determined.
    """
    if "://" not in url:
        url = "http://" + url

    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    return hostname.lower()


def _extract_tld(domain: str) -> str:
    """Extract the top-level domain from a domain string.

    Returns the TLD prefixed with a dot (e.g. ``".com"``). For
    IP-address domains or empty strings, returns an empty string.
    """
    if not domain or _IP_PATTERN.match(domain):
        return ""

    parts = domain.rsplit(".", 1)
    if len(parts) == 2:
        return "." + parts[1]
    return ""


def _count_suspicious_words(url: str) -> int:
    """Count occurrences of suspicious phishing-related words in a URL.

    The search is case-insensitive.
    """
    url_lower = url.lower()
    return sum(1 for word in SUSPICIOUS_WORDS if word in url_lower)


# ---------------------------------------------------------------------------
# URLClassifier
# ---------------------------------------------------------------------------


class URLClassifier:
    """Random Forest classifier for URL phishing / malicious-URL detection.

    Extracts 22 lexical features from each URL and classifies it as
    ``"benign"``, ``"suspicious"``, or ``"malicious"`` with an associated
    confidence score.

    Example::

        clf = URLClassifier()
        clf.train(urls, labels)
        label, confidence = clf.predict("https://example.com/login")
    """

    def __init__(
        self,
        n_estimators: int = 200,
        max_depth: int = 20,
    ) -> None:
        self._n_estimators = n_estimators
        self._max_depth = max_depth
        self._model: RandomForestClassifier | None = None
        self._is_trained = False

    # -- Properties ---------------------------------------------------------

    @property
    def is_trained(self) -> bool:
        """Whether the model has been fitted on training data."""
        return self._is_trained

    @property
    def feature_names(self) -> list[str]:
        """The 22 feature names extracted from each URL."""
        return list(FEATURE_NAMES)

    # -- Feature extraction -------------------------------------------------

    def extract_features(self, url: str) -> np.ndarray:
        """Extract all 22 lexical features from a URL string.

        Args:
            url: The URL to analyse. May or may not include a scheme.

        Returns:
            1-D numpy array of shape ``(22,)`` with ``float64`` dtype.
        """
        # Ensure a scheme is present for urlparse
        url_for_parse = url if "://" in url else "http://" + url
        parsed = urlparse(url_for_parse)

        domain = (parsed.hostname or "").lower()
        path = parsed.path or ""

        # 1. url_length
        url_length = float(len(url))

        # 2. domain_length
        domain_length = float(len(domain))

        # 3. subdomain_depth --- number of dots in domain minus one for TLD
        domain_parts = domain.split(".") if domain else []
        subdomain_depth = float(max(0, len(domain_parts) - 2))

        # 4. path_depth --- number of non-empty path segments
        path_segments = [s for s in path.split("/") if s]
        path_depth = float(len(path_segments))

        # 5. special_char_count
        special_char_count = float(
            sum(1 for ch in url if ch in _SPECIAL_CHARS)
        )

        # 6. digit_ratio
        digit_count = sum(1 for ch in url if ch.isdigit())
        digit_ratio = digit_count / len(url) if url else 0.0

        # 7. has_https
        has_https = 1.0 if url.lower().startswith("https") else 0.0

        # 8. has_ip_address
        has_ip_address = 1.0 if _IP_PATTERN.match(domain) else 0.0

        # 9. domain_entropy
        domain_entropy = _shannon_entropy(domain)

        # 10. tld_reputation
        tld = _extract_tld(domain)
        tld_reputation = TLD_REPUTATION.get(
            tld, _TLD_DEFAULT_REPUTATION
        )

        # 11. query_param_count
        query = parsed.query or ""
        query_param_count = float(
            len([p for p in query.split("&") if p]) if query else 0
        )

        # 12. has_punycode
        has_punycode = 1.0 if "xn--" in domain else 0.0

        # 13. brand_similarity (normalised 0-1, 1 = exact match)
        brand_similarity = self._brand_similarity(domain)

        # 14. has_at_symbol
        has_at_symbol = 1.0 if "@" in url else 0.0

        # 15. has_double_slash_redirect --- // anywhere in path
        has_double_slash_redirect = 1.0 if "//" in path else 0.0

        # 16. has_dash_in_domain
        has_dash_in_domain = 1.0 if "-" in domain else 0.0

        # 17. path_length
        path_length = float(len(path))

        # 18. has_port
        has_port = 1.0 if parsed.port is not None else 0.0

        # 19. letter_ratio
        letter_count = sum(1 for ch in url if ch.isalpha())
        letter_ratio = letter_count / len(url) if url else 0.0

        # 20. dot_count
        dot_count = float(url.count("."))

        # 21. has_encoded_chars
        has_encoded_chars = (
            1.0 if _ENCODED_CHAR_PATTERN.search(url) else 0.0
        )

        # 22. suspicious_word_count
        suspicious_word_count = float(_count_suspicious_words(url))

        features = np.array(
            [
                url_length,
                domain_length,
                subdomain_depth,
                path_depth,
                special_char_count,
                digit_ratio,
                has_https,
                has_ip_address,
                domain_entropy,
                tld_reputation,
                query_param_count,
                has_punycode,
                brand_similarity,
                has_at_symbol,
                has_double_slash_redirect,
                has_dash_in_domain,
                path_length,
                has_port,
                letter_ratio,
                dot_count,
                has_encoded_chars,
                suspicious_word_count,
            ],
            dtype=np.float64,
        )

        return features

    # -- Training -----------------------------------------------------------

    def train(self, urls: list[str], labels: list[int]) -> None:
        """Train the Random Forest on labelled URL data.

        Args:
            urls: List of raw URL strings.
            labels: Corresponding labels --- ``0`` for benign,
                ``1`` for malicious.

        Raises:
            ValueError: If fewer than ``MIN_TRAINING_SAMPLES`` are
                provided or if *urls* and *labels* differ in length.
        """
        if len(urls) != len(labels):
            raise ValueError(
                f"urls and labels must have the same length, "
                f"got {len(urls)} and {len(labels)}"
            )

        if len(urls) < MIN_TRAINING_SAMPLES:
            raise ValueError(
                f"Need at least {MIN_TRAINING_SAMPLES} samples to "
                f"train, got {len(urls)}"
            )

        logger.info(
            "Extracting features from %d URLs for training...",
            len(urls),
        )

        feature_matrix = np.array(
            [self.extract_features(u) for u in urls],
            dtype=np.float64,
        )

        self._model = RandomForestClassifier(
            n_estimators=self._n_estimators,
            max_depth=self._max_depth,
            random_state=42,
            n_jobs=-1,
        )
        self._model.fit(feature_matrix, labels)
        self._is_trained = True

        logger.info(
            "URLClassifier trained on %d samples "
            "(%d benign, %d malicious)",
            len(labels),
            labels.count(0),
            labels.count(1),
        )

    # -- Prediction ---------------------------------------------------------

    def predict(self, url: str) -> tuple[str, float]:
        """Classify a single URL.

        Args:
            url: The URL string to classify.

        Returns:
            A tuple ``(classification, confidence)`` where
            *classification* is one of ``"benign"``, ``"suspicious"``,
            or ``"malicious"`` and *confidence* is a float in
            ``[0, 1]``.

        Raises:
            RuntimeError: If the model has not been trained yet.
        """
        if not self._is_trained or self._model is None:
            raise RuntimeError(
                "URLClassifier has not been trained yet"
            )

        features = self.extract_features(url).reshape(1, -1)
        proba = self._model.predict_proba(features)[0]

        # proba layout depends on classes_ order
        classes = list(self._model.classes_)
        malicious_idx = classes.index(1) if 1 in classes else 0
        malicious_prob = float(proba[malicious_idx])

        classification = self._classify_probability(malicious_prob)
        confidence = self._compute_confidence(malicious_prob)

        return classification, round(confidence, 4)

    def predict_batch(
        self, urls: list[str],
    ) -> list[tuple[str, float]]:
        """Classify a batch of URLs.

        Args:
            urls: List of URL strings to classify.

        Returns:
            List of ``(classification, confidence)`` tuples, one
            per URL.

        Raises:
            RuntimeError: If the model has not been trained yet.
        """
        if not self._is_trained or self._model is None:
            raise RuntimeError(
                "URLClassifier has not been trained yet"
            )

        if not urls:
            return []

        feature_matrix = np.array(
            [self.extract_features(u) for u in urls],
            dtype=np.float64,
        )

        probas = self._model.predict_proba(feature_matrix)

        classes = list(self._model.classes_)
        malicious_idx = classes.index(1) if 1 in classes else 0

        results: list[tuple[str, float]] = []
        for proba in probas:
            malicious_prob = float(proba[malicious_idx])
            classification = self._classify_probability(
                malicious_prob
            )
            confidence = self._compute_confidence(malicious_prob)
            results.append(
                (classification, round(confidence, 4))
            )

        return results

    # -- Private helpers ----------------------------------------------------

    @staticmethod
    def _classify_probability(malicious_prob: float) -> str:
        """Map malicious probability to a classification label."""
        if malicious_prob >= 0.7:
            return "malicious"
        elif malicious_prob >= 0.5:
            return "suspicious"
        return "benign"

    @staticmethod
    def _compute_confidence(malicious_prob: float) -> float:
        """Derive confidence from the dominant class probability.

        Confidence reflects how certain the model is about its chosen
        classification, regardless of which class was picked.
        """
        return max(malicious_prob, 1.0 - malicious_prob)

    @staticmethod
    def _brand_similarity(domain: str) -> float:
        """Compute normalised brand-similarity score for a domain.

        Returns a value in ``[0, 1]`` where ``1.0`` means the domain
        contains an exact brand name, and values closer to ``0`` mean
        no resemblance.
        """
        if not domain:
            return 0.0

        # Strip TLD for comparison
        base = domain.rsplit(".", 1)[0] if "." in domain else domain

        min_distance = float("inf")
        best_brand_len = 1

        for brand in TOP_BRANDS:
            dist = _levenshtein_distance(base, brand)
            if dist < min_distance:
                min_distance = dist
                best_brand_len = max(len(brand), len(base))

        # Normalise: 0 distance -> 1.0 similarity, large distance -> 0.0
        similarity = max(
            0.0, 1.0 - (min_distance / best_brand_len)
        )
        return round(similarity, 4)
