"""DNS threat analyzer — detects tunneling, DGA domains, and DoH evasion.

Analyzes DNS query events produced by the network sensor to identify
DNS-based attack techniques.  Operates as a detection engine plugged
into the DetectionPipeline.

MITRE coverage: T1071.004 (DNS), T1048.003 (Exfiltration via DNS),
T1568.002 (Domain Generation Algorithms).
"""

from __future__ import annotations

import logging
import math
import time
from collections import Counter, defaultdict, deque
from dataclasses import dataclass, field
from typing import Any, Callable

logger = logging.getLogger(__name__)

# Known DNS-over-HTTPS provider IPs
DOH_PROVIDERS: set[str] = {
    "1.1.1.1", "1.0.0.1",                      # Cloudflare
    "8.8.8.8", "8.8.4.4",                      # Google
    "9.9.9.9", "149.112.112.112",              # Quad9
    "208.67.222.222", "208.67.220.220",        # OpenDNS
    "94.140.14.14", "94.140.15.15",            # AdGuard
}

# Known browser process names (DoH from these is expected)
BROWSER_PROCESSES: set[str] = {
    "chrome.exe", "firefox.exe", "msedge.exe", "brave.exe",
    "opera.exe", "vivaldi.exe", "iexplore.exe", "safari.exe",
}

# Suspicious TLDs often used by malware
SUSPICIOUS_TLDS: set[str] = {
    "tk", "ml", "ga", "cf", "gq",  # Free TLDs abused by malware
    "xyz", "top", "buzz", "club", "work", "date", "racing",
    "download", "stream", "bid", "loan",
}

# English bigram frequencies (top 30, normalised to ~1.0 scale)
_ENGLISH_BIGRAMS: dict[str, float] = {
    "th": 3.56, "he": 3.07, "in": 2.43, "er": 2.05, "an": 1.99,
    "re": 1.85, "on": 1.76, "at": 1.49, "en": 1.45, "nd": 1.35,
    "ti": 1.34, "es": 1.34, "or": 1.28, "te": 1.27, "of": 1.17,
    "ed": 1.17, "is": 1.13, "it": 1.12, "al": 1.09, "ar": 1.07,
    "st": 1.05, "to": 1.04, "nt": 1.04, "ng": 0.95, "se": 0.93,
    "ha": 0.93, "as": 0.87, "ou": 0.87, "io": 0.83, "le": 0.83,
}


@dataclass
class DNSAnalysisResult:
    """Result of analysing a DNS query."""

    is_suspicious: bool
    threat_type: str  # "tunneling", "dga", "doh_evasion", "suspicious_tld", ""
    confidence: float
    details: dict[str, Any] = field(default_factory=dict)


class DNSAnalyzer:
    """DNS threat detection engine.

    Maintains a sliding window of recent DNS queries for statistical
    analysis.  Detects tunneling, DGA, and DoH evasion patterns.
    """

    def __init__(
        self,
        window_size: int = 1000,
        tunneling_entropy_threshold: float = 3.5,
        tunneling_length_threshold: int = 50,
        dga_entropy_threshold: float = 3.8,
        query_rate_threshold: int = 30,
        ioc_lookup: Callable[[str], dict[str, Any] | None] | None = None,
    ) -> None:
        self._window_size = window_size
        self._tunneling_entropy_threshold = tunneling_entropy_threshold
        self._tunneling_length_threshold = tunneling_length_threshold
        self._dga_entropy_threshold = dga_entropy_threshold
        self._query_rate_threshold = query_rate_threshold
        self._ioc_lookup = ioc_lookup

        # Sliding windows for statistical analysis
        self._query_history: deque[tuple[float, str]] = deque(maxlen=window_size)
        self._domain_rate: dict[str, deque[float]] = defaultdict(
            lambda: deque(maxlen=200),
        )

    def analyze_query(self, query_name: str, **kwargs: Any) -> DNSAnalysisResult | None:
        """Analyze a DNS query.

        Parameters
        ----------
        query_name : str
            The queried domain name.
        **kwargs :
            Optional context: ``process_name``, ``remote_addr``,
            ``remote_port``, ``query_type``.

        Returns analysis result if suspicious, ``None`` if benign.
        """
        if not query_name:
            return None

        now = time.time()
        self._query_history.append((now, query_name))
        base_domain = self._extract_base_domain(query_name)
        self._domain_rate[base_domain].append(now)

        # 1. Check IOC database
        if self._ioc_lookup:
            ioc = self._ioc_lookup(query_name)
            if ioc is not None:
                return DNSAnalysisResult(
                    is_suspicious=True,
                    threat_type="known_malicious",
                    confidence=0.95,
                    details={"ioc": ioc, "domain": query_name},
                )

        # 2. DNS tunneling detection
        is_tunnel, tunnel_conf, tunnel_details = self.detect_tunneling(
            query_name, base_domain, now,
        )
        if is_tunnel:
            return DNSAnalysisResult(
                is_suspicious=True,
                threat_type="tunneling",
                confidence=tunnel_conf,
                details=tunnel_details,
            )

        # 3. DGA detection
        is_dga, dga_conf = self.detect_dga(base_domain)
        if is_dga:
            return DNSAnalysisResult(
                is_suspicious=True,
                threat_type="dga",
                confidence=dga_conf,
                details={"domain": query_name, "base_domain": base_domain},
            )

        # 4. DoH evasion detection
        process_name = kwargs.get("process_name", "")
        remote_addr = kwargs.get("remote_addr", "")
        remote_port = kwargs.get("remote_port", 0)
        if remote_addr and process_name:
            is_doh, doh_conf = self.detect_doh_evasion(
                remote_addr, remote_port, process_name,
            )
            if is_doh:
                return DNSAnalysisResult(
                    is_suspicious=True,
                    threat_type="doh_evasion",
                    confidence=doh_conf,
                    details={
                        "process": process_name,
                        "remote_addr": remote_addr,
                        "domain": query_name,
                    },
                )

        # 5. Suspicious TLD check
        tld = query_name.rsplit(".", 1)[-1].lower() if "." in query_name else ""
        if tld in SUSPICIOUS_TLDS:
            return DNSAnalysisResult(
                is_suspicious=True,
                threat_type="suspicious_tld",
                confidence=0.4,
                details={"domain": query_name, "tld": tld},
            )

        return None

    def detect_tunneling(
        self, query_name: str, base_domain: str, now: float,
    ) -> tuple[bool, float, dict[str, Any]]:
        """Detect DNS tunneling.

        Indicators:
        - High subdomain entropy (random-looking labels)
        - Long subdomain string (>50 chars)
        - High query rate to a single base domain
        """
        subdomain = self._extract_subdomain(query_name)
        details: dict[str, Any] = {"domain": query_name}
        confidence = 0.0

        # Subdomain entropy
        entropy = self._string_entropy(subdomain)
        details["subdomain_entropy"] = round(entropy, 4)
        if entropy > self._tunneling_entropy_threshold and len(subdomain) > 10:
            confidence += 0.4

        # Subdomain length
        details["subdomain_length"] = len(subdomain)
        if len(subdomain) > self._tunneling_length_threshold:
            confidence += 0.3

        # Query rate to base domain
        rate = self._queries_per_minute(base_domain, now)
        details["queries_per_minute"] = rate
        if rate > self._query_rate_threshold:
            confidence += 0.3

        is_tunnel = confidence >= 0.6
        return is_tunnel, min(confidence, 1.0), details

    def detect_dga(self, domain: str) -> tuple[bool, float]:
        """Detect algorithmically generated domains.

        Uses bigram frequency analysis and consonant ratio.
        """
        # Strip TLD for analysis
        parts = domain.split(".")
        label = parts[0] if parts else domain
        if len(label) < 5:
            return False, 0.0

        # 1. Character entropy
        entropy = self._string_entropy(label)
        if entropy < self._dga_entropy_threshold:
            return False, 0.0

        # 2. Bigram score (low = likely random)
        bigram_score = self._bigram_score(label)

        # 3. Consonant ratio
        vowels = set("aeiou")
        consonants = sum(1 for c in label.lower() if c.isalpha() and c not in vowels)
        alpha_count = sum(1 for c in label.lower() if c.isalpha())
        consonant_ratio = consonants / alpha_count if alpha_count > 0 else 0.5

        # Combine signals
        confidence = 0.0
        if entropy > self._dga_entropy_threshold:
            confidence += 0.3
        if bigram_score < 0.5:
            confidence += 0.35
        if consonant_ratio > 0.75:
            confidence += 0.2
        if len(label) > 12:
            confidence += 0.15

        is_dga = confidence >= 0.6
        return is_dga, round(min(confidence, 1.0), 3)

    def detect_doh_evasion(
        self, remote_addr: str, remote_port: int, process_name: str,
    ) -> tuple[bool, float]:
        """Detect DNS-over-HTTPS from non-browser processes.

        A non-browser process connecting to a known DoH provider IP
        on port 443 is suspicious — it may be bypassing local DNS
        monitoring.
        """
        if remote_addr not in DOH_PROVIDERS:
            return False, 0.0
        if remote_port not in (443, 8443):
            return False, 0.0
        if process_name.lower() in BROWSER_PROCESSES:
            return False, 0.0

        # Non-browser process using DoH
        return True, 0.8

    @staticmethod
    def _string_entropy(s: str) -> float:
        """Shannon entropy of a string."""
        if not s:
            return 0.0
        freq = Counter(s.lower())
        total = len(s)
        entropy = 0.0
        for count in freq.values():
            p = count / total
            if p > 0:
                entropy -= p * math.log2(p)
        return round(entropy, 4)

    @staticmethod
    def _bigram_score(s: str) -> float:
        """Score a string using English bigram frequency.

        Higher score = more like natural English; lower = more random.
        Returns normalised score 0.0 - 1.0.
        """
        s = s.lower()
        if len(s) < 2:
            return 0.5
        total = 0.0
        count = 0
        for i in range(len(s) - 1):
            bigram = s[i:i + 2]
            if bigram.isalpha():
                total += _ENGLISH_BIGRAMS.get(bigram, 0.0)
                count += 1
        if count == 0:
            return 0.0
        avg = total / count
        # Normalise: typical English text scores ~1.2-1.5
        return round(min(avg / 2.0, 1.0), 4)

    @staticmethod
    def _extract_base_domain(fqdn: str) -> str:
        """Extract base domain (last two labels) from FQDN."""
        parts = fqdn.rstrip(".").split(".")
        if len(parts) >= 2:
            return ".".join(parts[-2:])
        return fqdn

    @staticmethod
    def _extract_subdomain(fqdn: str) -> str:
        """Extract subdomain portion (everything except last two labels)."""
        parts = fqdn.rstrip(".").split(".")
        if len(parts) > 2:
            return ".".join(parts[:-2])
        return ""

    def _queries_per_minute(self, base_domain: str, now: float) -> int:
        """Count queries to a base domain in the last 60 seconds."""
        timestamps = self._domain_rate.get(base_domain)
        if not timestamps:
            return 0
        cutoff = now - 60.0
        return sum(1 for t in timestamps if t > cutoff)
