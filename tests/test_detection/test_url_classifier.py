"""Tests for the Random Forest URL/Phishing classifier engine."""

from __future__ import annotations

import random

import numpy as np
import pytest

from aegis.detection.url_classifier import (
    MIN_TRAINING_SAMPLES,
    URLClassifier,
    _count_suspicious_words,
    _extract_domain,
    _extract_tld,
    _levenshtein_distance,
    _shannon_entropy,
)

# ---------------------------------------------------------------------------
# Helper: generate labelled training data
# ---------------------------------------------------------------------------

def _generate_training_data(
    n_benign: int = 80,
    n_malicious: int = 40,
    seed: int = 42,
) -> tuple[list[str], list[int]]:
    """Create synthetic benign and malicious URLs for training."""
    rng = random.Random(seed)

    benign_domains = [
        "google.com",
        "github.com",
        "stackoverflow.com",
        "python.org",
        "wikipedia.org",
        "microsoft.com",
        "apple.com",
        "amazon.com",
        "youtube.com",
        "reddit.com",
        "linkedin.com",
        "twitter.com",
        "medium.com",
        "bbc.co.uk",
        "cnn.com",
    ]

    urls: list[str] = []
    labels: list[int] = []

    for i in range(n_benign):
        domain = rng.choice(benign_domains)
        urls.append(f"https://www.{domain}/page{i}")
        labels.append(0)

    for i in range(n_malicious):
        ip = (
            f"{rng.randint(1, 255)}.{rng.randint(1, 255)}"
            f".{rng.randint(1, 255)}.{rng.randint(1, 255)}"
        )
        token = rng.randint(1000, 9999)
        urls.append(
            f"http://{ip}/login/verify/account{i}?id={token}"
        )
        labels.append(1)

    return urls, labels


# ---------------------------------------------------------------------------
# Initialization
# ---------------------------------------------------------------------------


class TestURLClassifierInit:
    """URLClassifier construction and default parameters."""

    def test_default_init(self) -> None:
        clf = URLClassifier()
        assert clf._n_estimators == 200
        assert clf._max_depth == 20
        assert clf.is_trained is False

    def test_custom_params(self) -> None:
        clf = URLClassifier(n_estimators=50, max_depth=10)
        assert clf._n_estimators == 50
        assert clf._max_depth == 10
        assert clf.is_trained is False

    def test_model_starts_none(self) -> None:
        clf = URLClassifier()
        assert clf._model is None


# ---------------------------------------------------------------------------
# Properties
# ---------------------------------------------------------------------------


class TestURLClassifierProperties:
    """is_trained and feature_names properties."""

    def test_is_trained_false_initially(self) -> None:
        clf = URLClassifier()
        assert clf.is_trained is False

    def test_feature_names_returns_list_of_strings(self) -> None:
        clf = URLClassifier()
        names = clf.feature_names
        assert isinstance(names, list)
        assert all(isinstance(n, str) for n in names)

    def test_feature_names_has_22_entries(self) -> None:
        clf = URLClassifier()
        assert len(clf.feature_names) == 22

    def test_feature_names_returns_copy(self) -> None:
        clf = URLClassifier()
        names = clf.feature_names
        names.append("extra")
        assert len(clf.feature_names) == 22  # original unchanged


# ---------------------------------------------------------------------------
# Feature extraction — shape and dtype
# ---------------------------------------------------------------------------


class TestExtractFeaturesShape:
    """extract_features returns a correct numpy array."""

    def test_returns_ndarray(self) -> None:
        clf = URLClassifier()
        features = clf.extract_features("https://example.com")
        assert isinstance(features, np.ndarray)

    def test_shape_is_22(self) -> None:
        clf = URLClassifier()
        features = clf.extract_features("https://example.com")
        assert features.shape == (22,)

    def test_dtype_is_float64(self) -> None:
        clf = URLClassifier()
        features = clf.extract_features("https://example.com")
        assert features.dtype == np.float64


# ---------------------------------------------------------------------------
# Feature extraction — benign URL
# ---------------------------------------------------------------------------


class TestExtractFeaturesBenign:
    """Feature values for a simple benign URL."""

    URL = "https://www.google.com"

    def test_url_length(self) -> None:
        clf = URLClassifier()
        f = clf.extract_features(self.URL)
        assert f[0] == float(len(self.URL))

    def test_has_https_is_1(self) -> None:
        clf = URLClassifier()
        f = clf.extract_features(self.URL)
        assert f[6] == 1.0

    def test_has_ip_address_is_0(self) -> None:
        clf = URLClassifier()
        f = clf.extract_features(self.URL)
        assert f[7] == 0.0

    def test_tld_reputation_com(self) -> None:
        clf = URLClassifier()
        f = clf.extract_features(self.URL)
        assert f[9] == 1.0  # .com

    def test_has_punycode_is_0(self) -> None:
        clf = URLClassifier()
        f = clf.extract_features(self.URL)
        assert f[11] == 0.0

    def test_has_encoded_chars_is_0(self) -> None:
        clf = URLClassifier()
        f = clf.extract_features(self.URL)
        assert f[20] == 0.0

    def test_suspicious_word_count_is_0(self) -> None:
        clf = URLClassifier()
        f = clf.extract_features(self.URL)
        assert f[21] == 0.0


# ---------------------------------------------------------------------------
# Feature extraction — suspicious / malicious URL
# ---------------------------------------------------------------------------


class TestExtractFeaturesSuspicious:
    """Feature values for URLs with suspicious characteristics."""

    def test_ip_address_detected(self) -> None:
        clf = URLClassifier()
        url = "http://192.168.1.1/login/verify/account"
        f = clf.extract_features(url)
        assert f[7] == 1.0  # has_ip_address

    def test_encoded_chars_detected(self) -> None:
        clf = URLClassifier()
        url = "http://evil.com/path%20with%2Fencoded"
        f = clf.extract_features(url)
        assert f[20] == 1.0  # has_encoded_chars

    def test_long_path_has_higher_path_depth(self) -> None:
        clf = URLClassifier()
        url = "http://evil.com/a/b/c/d/e/f"
        f = clf.extract_features(url)
        assert f[3] >= 6.0  # path_depth

    def test_suspicious_words_counted(self) -> None:
        clf = URLClassifier()
        url = "http://evil.com/login/verify/account/secure"
        f = clf.extract_features(url)
        assert f[21] >= 4.0  # login, verify, account, secure

    def test_no_https(self) -> None:
        clf = URLClassifier()
        url = "http://evil.com/phish"
        f = clf.extract_features(url)
        assert f[6] == 0.0  # has_https


# ---------------------------------------------------------------------------
# Feature extraction — punycode
# ---------------------------------------------------------------------------


class TestExtractFeaturesPunycode:
    """URLs containing punycode (xn--)."""

    def test_punycode_detected(self) -> None:
        clf = URLClassifier()
        url = "http://xn--pple-43d.com/login"
        f = clf.extract_features(url)
        assert f[11] == 1.0  # has_punycode

    def test_no_punycode(self) -> None:
        clf = URLClassifier()
        url = "https://apple.com"
        f = clf.extract_features(url)
        assert f[11] == 0.0


# ---------------------------------------------------------------------------
# Feature extraction — port
# ---------------------------------------------------------------------------


class TestExtractFeaturesPort:
    """URLs with explicit port numbers."""

    def test_port_detected(self) -> None:
        clf = URLClassifier()
        url = "http://example.com:8080/admin"
        f = clf.extract_features(url)
        assert f[17] == 1.0  # has_port

    def test_no_port(self) -> None:
        clf = URLClassifier()
        url = "https://example.com/admin"
        f = clf.extract_features(url)
        assert f[17] == 0.0


# ---------------------------------------------------------------------------
# Feature extraction — query params
# ---------------------------------------------------------------------------


class TestExtractFeaturesQueryParams:
    """Query parameter counting."""

    def test_no_params(self) -> None:
        clf = URLClassifier()
        f = clf.extract_features("https://example.com/page")
        assert f[10] == 0.0

    def test_single_param(self) -> None:
        clf = URLClassifier()
        f = clf.extract_features("https://example.com/page?id=1")
        assert f[10] == 1.0

    def test_multiple_params(self) -> None:
        clf = URLClassifier()
        url = "https://example.com/page?a=1&b=2&c=3"
        f = clf.extract_features(url)
        assert f[10] == 3.0


# ---------------------------------------------------------------------------
# has_https detection
# ---------------------------------------------------------------------------


class TestHasHttps:
    """has_https feature (index 6)."""

    def test_https_url(self) -> None:
        clf = URLClassifier()
        f = clf.extract_features("https://secure.example.com")
        assert f[6] == 1.0

    def test_http_url(self) -> None:
        clf = URLClassifier()
        f = clf.extract_features("http://insecure.example.com")
        assert f[6] == 0.0


# ---------------------------------------------------------------------------
# has_ip_address detection
# ---------------------------------------------------------------------------


class TestHasIpAddress:
    """has_ip_address feature (index 7)."""

    def test_ip_url(self) -> None:
        clf = URLClassifier()
        f = clf.extract_features("http://10.0.0.1/page")
        assert f[7] == 1.0

    def test_domain_url(self) -> None:
        clf = URLClassifier()
        f = clf.extract_features("https://example.com/page")
        assert f[7] == 0.0


# ---------------------------------------------------------------------------
# brand_similarity scoring
# ---------------------------------------------------------------------------


class TestBrandSimilarity:
    """brand_similarity feature (index 12)."""

    def test_exact_brand_domain(self) -> None:
        clf = URLClassifier()
        f = clf.extract_features("https://paypal.com/login")
        # "paypal" vs "paypal" -> distance 0 -> similarity 1.0
        assert f[12] == 1.0

    def test_close_brand_typosquat(self) -> None:
        clf = URLClassifier()
        f = clf.extract_features("http://paypal-secure.tk/login")
        # "paypal-secure" is close to "paypal" so similarity > 0
        assert f[12] > 0.0

    def test_unrelated_domain(self) -> None:
        clf = URLClassifier()
        f = clf.extract_features("https://xyzzyqwert.com")
        # Very different from any brand -> low similarity
        assert f[12] < 0.5


# ---------------------------------------------------------------------------
# tld_reputation
# ---------------------------------------------------------------------------


class TestTldReputation:
    """tld_reputation feature (index 9)."""

    def test_com_tld(self) -> None:
        clf = URLClassifier()
        f = clf.extract_features("https://example.com")
        assert f[9] == 1.0

    def test_tk_tld(self) -> None:
        clf = URLClassifier()
        f = clf.extract_features("http://evil.tk")
        assert f[9] == 0.1

    def test_unknown_tld_gets_default(self) -> None:
        clf = URLClassifier()
        f = clf.extract_features("https://example.zzzzzz")
        assert f[9] == 0.5  # _TLD_DEFAULT_REPUTATION

    def test_gov_tld(self) -> None:
        clf = URLClassifier()
        f = clf.extract_features("https://whitehouse.gov")
        assert f[9] == 1.0


# ---------------------------------------------------------------------------
# suspicious_word_count
# ---------------------------------------------------------------------------


class TestSuspiciousWordCount:
    """suspicious_word_count feature (index 21)."""

    def test_no_suspicious_words(self) -> None:
        clf = URLClassifier()
        f = clf.extract_features("https://example.com/about")
        assert f[21] == 0.0

    def test_one_suspicious_word(self) -> None:
        clf = URLClassifier()
        f = clf.extract_features("https://example.com/login")
        assert f[21] >= 1.0

    def test_many_suspicious_words(self) -> None:
        clf = URLClassifier()
        url = "http://evil.com/login/verify/secure/account/password"
        f = clf.extract_features(url)
        assert f[21] >= 5.0


# ---------------------------------------------------------------------------
# Training
# ---------------------------------------------------------------------------


class TestTraining:
    """URLClassifier.train validation and success."""

    def test_train_with_valid_data(self) -> None:
        clf = URLClassifier(n_estimators=10, max_depth=5)
        urls, labels = _generate_training_data(80, 40)
        clf.train(urls, labels)
        assert clf.is_trained is True

    def test_train_mismatched_lengths_raises(self) -> None:
        clf = URLClassifier()
        urls = ["https://example.com"] * 120
        labels = [0] * 100
        with pytest.raises(ValueError, match="same length"):
            clf.train(urls, labels)

    def test_train_insufficient_samples_raises(self) -> None:
        clf = URLClassifier()
        urls = ["https://example.com"] * 50
        labels = [0] * 50
        with pytest.raises(ValueError, match="at least"):
            clf.train(urls, labels)

    def test_train_exactly_min_samples(self) -> None:
        clf = URLClassifier(n_estimators=10, max_depth=5)
        urls, labels = _generate_training_data(
            n_benign=70, n_malicious=30,
        )
        assert len(urls) == MIN_TRAINING_SAMPLES
        clf.train(urls, labels)
        assert clf.is_trained is True

    def test_train_sets_model(self) -> None:
        clf = URLClassifier(n_estimators=10, max_depth=5)
        urls, labels = _generate_training_data(80, 40)
        clf.train(urls, labels)
        assert clf._model is not None


# ---------------------------------------------------------------------------
# Prediction — single URL
# ---------------------------------------------------------------------------


class TestPredict:
    """URLClassifier.predict on single URLs."""

    @pytest.fixture()
    def trained_clf(self) -> URLClassifier:
        clf = URLClassifier(n_estimators=30, max_depth=10)
        urls, labels = _generate_training_data(80, 40, seed=1)
        clf.train(urls, labels)
        return clf

    def test_predict_returns_tuple(self, trained_clf: URLClassifier) -> None:
        result = trained_clf.predict("https://www.google.com")
        assert isinstance(result, tuple)
        assert len(result) == 2

    def test_predict_classification_is_string(
        self, trained_clf: URLClassifier,
    ) -> None:
        classification, _ = trained_clf.predict("https://www.google.com")
        assert isinstance(classification, str)
        assert classification in {"benign", "suspicious", "malicious"}

    def test_predict_confidence_is_float(
        self, trained_clf: URLClassifier,
    ) -> None:
        _, confidence = trained_clf.predict("https://www.google.com")
        assert isinstance(confidence, float)
        assert 0.0 <= confidence <= 1.0

    def test_predict_untrained_raises(self) -> None:
        clf = URLClassifier()
        with pytest.raises(RuntimeError, match="not been trained"):
            clf.predict("https://example.com")

    def test_predict_benign_url(self, trained_clf: URLClassifier) -> None:
        classification, confidence = trained_clf.predict(
            "https://www.google.com/search?q=python"
        )
        # A well-known benign URL should be classified as benign
        assert classification == "benign"
        assert confidence >= 0.5

    def test_predict_malicious_url(self, trained_clf: URLClassifier) -> None:
        classification, confidence = trained_clf.predict(
            "http://192.168.1.1/login/verify/account?id=1234"
        )
        # An IP-based URL with suspicious words should not be benign
        assert classification in {"suspicious", "malicious"}
        assert confidence >= 0.5


# ---------------------------------------------------------------------------
# Prediction — batch
# ---------------------------------------------------------------------------


class TestPredictBatch:
    """URLClassifier.predict_batch."""

    @pytest.fixture()
    def trained_clf(self) -> URLClassifier:
        clf = URLClassifier(n_estimators=30, max_depth=10)
        urls, labels = _generate_training_data(80, 40, seed=2)
        clf.train(urls, labels)
        return clf

    def test_batch_returns_list(self, trained_clf: URLClassifier) -> None:
        results = trained_clf.predict_batch(["https://google.com"])
        assert isinstance(results, list)

    def test_batch_returns_correct_count(
        self, trained_clf: URLClassifier,
    ) -> None:
        urls = [
            "https://google.com",
            "http://evil.tk/login",
            "https://github.com",
        ]
        results = trained_clf.predict_batch(urls)
        assert len(results) == 3

    def test_batch_each_element_is_tuple(
        self, trained_clf: URLClassifier,
    ) -> None:
        results = trained_clf.predict_batch(["https://google.com"])
        for item in results:
            assert isinstance(item, tuple)
            assert len(item) == 2

    def test_batch_empty_list_returns_empty(
        self, trained_clf: URLClassifier,
    ) -> None:
        results = trained_clf.predict_batch([])
        assert results == []

    def test_batch_untrained_raises(self) -> None:
        clf = URLClassifier()
        with pytest.raises(RuntimeError, match="not been trained"):
            clf.predict_batch(["https://example.com"])


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------


class TestShannonEntropy:
    """_shannon_entropy helper."""

    def test_empty_string(self) -> None:
        assert _shannon_entropy("") == 0.0

    def test_single_char(self) -> None:
        # All same char -> 0 entropy
        assert _shannon_entropy("aaaa") == 0.0

    def test_two_equal_chars(self) -> None:
        # "ab" -> 1.0 bit
        assert _shannon_entropy("ab") == 1.0

    def test_higher_entropy_with_variety(self) -> None:
        low = _shannon_entropy("aaa")
        high = _shannon_entropy("abc")
        assert high > low

    def test_returns_float(self) -> None:
        result = _shannon_entropy("hello")
        assert isinstance(result, float)


class TestLevenshteinDistance:
    """_levenshtein_distance helper."""

    def test_identical_strings(self) -> None:
        assert _levenshtein_distance("hello", "hello") == 0

    def test_empty_vs_nonempty(self) -> None:
        assert _levenshtein_distance("", "abc") == 3

    def test_both_empty(self) -> None:
        assert _levenshtein_distance("", "") == 0

    def test_single_substitution(self) -> None:
        assert _levenshtein_distance("cat", "car") == 1

    def test_insertion(self) -> None:
        assert _levenshtein_distance("abc", "abcd") == 1

    def test_symmetric(self) -> None:
        d1 = _levenshtein_distance("kitten", "sitting")
        d2 = _levenshtein_distance("sitting", "kitten")
        assert d1 == d2


class TestExtractDomain:
    """_extract_domain helper."""

    def test_full_url(self) -> None:
        assert _extract_domain("https://www.example.com/path") == "www.example.com"

    def test_url_without_scheme(self) -> None:
        assert _extract_domain("example.com/path") == "example.com"

    def test_ip_address(self) -> None:
        assert _extract_domain("http://10.0.0.1/page") == "10.0.0.1"

    def test_returns_lowercase(self) -> None:
        assert _extract_domain("https://EXAMPLE.COM") == "example.com"


class TestExtractTld:
    """_extract_tld helper."""

    def test_com_domain(self) -> None:
        assert _extract_tld("example.com") == ".com"

    def test_co_uk_gives_uk(self) -> None:
        # Simple split gives last dot segment
        assert _extract_tld("bbc.co.uk") == ".uk"

    def test_ip_address_returns_empty(self) -> None:
        assert _extract_tld("192.168.1.1") == ""

    def test_empty_string_returns_empty(self) -> None:
        assert _extract_tld("") == ""

    def test_single_part(self) -> None:
        assert _extract_tld("localhost") == ""


class TestCountSuspiciousWords:
    """_count_suspicious_words helper."""

    def test_no_matches(self) -> None:
        assert _count_suspicious_words("https://example.com") == 0

    def test_single_match(self) -> None:
        assert _count_suspicious_words("https://example.com/login") >= 1

    def test_multiple_matches(self) -> None:
        url = "http://evil.com/login/verify/account"
        count = _count_suspicious_words(url)
        assert count >= 3

    def test_case_insensitive(self) -> None:
        assert _count_suspicious_words("http://evil.com/LOGIN/VERIFY") >= 2


# ---------------------------------------------------------------------------
# Classification routing
# ---------------------------------------------------------------------------


class TestClassifyProbability:
    """URLClassifier._classify_probability static method."""

    def test_high_prob_is_malicious(self) -> None:
        assert URLClassifier._classify_probability(0.7) == "malicious"
        assert URLClassifier._classify_probability(0.9) == "malicious"

    def test_mid_prob_is_suspicious(self) -> None:
        assert URLClassifier._classify_probability(0.5) == "suspicious"
        assert URLClassifier._classify_probability(0.69) == "suspicious"

    def test_low_prob_is_benign(self) -> None:
        assert URLClassifier._classify_probability(0.0) == "benign"
        assert URLClassifier._classify_probability(0.49) == "benign"


class TestComputeConfidence:
    """URLClassifier._compute_confidence static method."""

    def test_malicious_confidence(self) -> None:
        # prob=0.9 -> confidence=0.9
        assert URLClassifier._compute_confidence(0.9) == 0.9

    def test_benign_confidence(self) -> None:
        # prob=0.1 -> confidence=0.9  (1.0 - 0.1)
        assert URLClassifier._compute_confidence(0.1) == 0.9

    def test_uncertain_confidence(self) -> None:
        # prob=0.5 -> confidence=0.5
        assert URLClassifier._compute_confidence(0.5) == 0.5
