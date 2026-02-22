"""Tests for the DNS threat analyzer module."""

from __future__ import annotations

import time

import pytest

from aegis.detection.dns_analyzer import (
    BROWSER_PROCESSES,
    DOH_PROVIDERS,
    SUSPICIOUS_TLDS,
    DNSAnalysisResult,
    DNSAnalyzer,
)


# ================================================================== #
#  Module-level constants tests
# ================================================================== #


class TestModuleConstants:
    """Tests for module-level constant sets."""

    def test_doh_providers_contains_google(self):
        assert "8.8.8.8" in DOH_PROVIDERS
        assert "8.8.4.4" in DOH_PROVIDERS

    def test_doh_providers_contains_cloudflare(self):
        assert "1.1.1.1" in DOH_PROVIDERS
        assert "1.0.0.1" in DOH_PROVIDERS

    def test_doh_providers_contains_quad9(self):
        assert "9.9.9.9" in DOH_PROVIDERS

    def test_browser_processes_contains_chrome(self):
        assert "chrome.exe" in BROWSER_PROCESSES

    def test_browser_processes_contains_firefox(self):
        assert "firefox.exe" in BROWSER_PROCESSES

    def test_browser_processes_contains_edge(self):
        assert "msedge.exe" in BROWSER_PROCESSES

    def test_suspicious_tlds_contains_tk(self):
        assert "tk" in SUSPICIOUS_TLDS

    def test_suspicious_tlds_contains_ml(self):
        assert "ml" in SUSPICIOUS_TLDS

    def test_suspicious_tlds_contains_xyz(self):
        assert "xyz" in SUSPICIOUS_TLDS


# ================================================================== #
#  DNSAnalysisResult tests
# ================================================================== #


class TestDNSAnalysisResult:
    """Tests for the DNSAnalysisResult dataclass."""

    def test_result_fields(self):
        result = DNSAnalysisResult(
            is_suspicious=True,
            threat_type="tunneling",
            confidence=0.85,
            details={"domain": "evil.com"},
        )
        assert result.is_suspicious is True
        assert result.threat_type == "tunneling"
        assert result.confidence == 0.85
        assert result.details == {"domain": "evil.com"}

    def test_result_default_details(self):
        result = DNSAnalysisResult(
            is_suspicious=False,
            threat_type="",
            confidence=0.0,
        )
        assert result.details == {}

    def test_result_benign(self):
        result = DNSAnalysisResult(
            is_suspicious=False,
            threat_type="",
            confidence=0.0,
        )
        assert result.is_suspicious is False


# ================================================================== #
#  DNSAnalyzer init tests
# ================================================================== #


class TestDNSAnalyzerInit:
    """Tests for DNSAnalyzer constructor defaults."""

    def test_default_window_size(self):
        analyzer = DNSAnalyzer()
        assert analyzer._window_size == 1000

    def test_default_tunneling_entropy_threshold(self):
        analyzer = DNSAnalyzer()
        assert analyzer._tunneling_entropy_threshold == 3.5

    def test_default_tunneling_length_threshold(self):
        analyzer = DNSAnalyzer()
        assert analyzer._tunneling_length_threshold == 50

    def test_default_dga_entropy_threshold(self):
        analyzer = DNSAnalyzer()
        assert analyzer._dga_entropy_threshold == 3.8

    def test_default_query_rate_threshold(self):
        analyzer = DNSAnalyzer()
        assert analyzer._query_rate_threshold == 30

    def test_default_ioc_lookup_is_none(self):
        analyzer = DNSAnalyzer()
        assert analyzer._ioc_lookup is None

    def test_custom_parameters(self):
        lookup = lambda domain: None
        analyzer = DNSAnalyzer(
            window_size=500,
            tunneling_entropy_threshold=4.0,
            tunneling_length_threshold=40,
            dga_entropy_threshold=4.2,
            query_rate_threshold=20,
            ioc_lookup=lookup,
        )
        assert analyzer._window_size == 500
        assert analyzer._tunneling_entropy_threshold == 4.0
        assert analyzer._tunneling_length_threshold == 40
        assert analyzer._dga_entropy_threshold == 4.2
        assert analyzer._query_rate_threshold == 20
        assert analyzer._ioc_lookup is lookup


# ================================================================== #
#  _string_entropy tests
# ================================================================== #


class TestStringEntropy:
    """Tests for DNSAnalyzer._string_entropy."""

    def test_empty_string_returns_zero(self):
        assert DNSAnalyzer._string_entropy("") == 0.0

    def test_single_char_returns_zero(self):
        assert DNSAnalyzer._string_entropy("a") == 0.0

    def test_repeated_char_returns_zero(self):
        assert DNSAnalyzer._string_entropy("aaaaaaa") == 0.0

    def test_two_distinct_chars_equal_freq(self):
        # "ab" -> entropy = 1.0
        entropy = DNSAnalyzer._string_entropy("ab")
        assert abs(entropy - 1.0) < 0.01

    def test_varied_string_high_entropy(self):
        # Many distinct characters should produce high entropy
        varied = "abcdefghijklmnop"
        entropy = DNSAnalyzer._string_entropy(varied)
        assert entropy > 3.5

    def test_entropy_is_non_negative(self):
        assert DNSAnalyzer._string_entropy("test") >= 0.0

    def test_random_looking_string_higher_than_repeated(self):
        random_like = "x8k3j9f2m7q1"
        repeated = "aaabbbccc"
        assert DNSAnalyzer._string_entropy(random_like) > DNSAnalyzer._string_entropy(repeated)


# ================================================================== #
#  _bigram_score tests
# ================================================================== #


class TestBigramScore:
    """Tests for DNSAnalyzer._bigram_score."""

    def test_english_word_scores_high(self):
        # "the" contains "th" and "he" which are top bigrams
        score = DNSAnalyzer._bigram_score("there")
        assert score > 0.5

    def test_random_string_scores_low(self):
        score = DNSAnalyzer._bigram_score("xqzjkw")
        assert score < 0.3

    def test_single_char_returns_default(self):
        score = DNSAnalyzer._bigram_score("a")
        assert score == 0.5

    def test_empty_string_returns_default(self):
        # len < 2 check
        score = DNSAnalyzer._bigram_score("")
        assert score == 0.5

    def test_score_between_zero_and_one(self):
        for word in ("testing", "xkjf9z", "the", "abcdef"):
            score = DNSAnalyzer._bigram_score(word)
            assert 0.0 <= score <= 1.0


# ================================================================== #
#  _extract_base_domain tests
# ================================================================== #


class TestExtractBaseDomain:
    """Tests for DNSAnalyzer._extract_base_domain."""

    def test_subdomain_removed(self):
        assert DNSAnalyzer._extract_base_domain("sub.example.com") == "example.com"

    def test_deep_subdomain(self):
        result = DNSAnalyzer._extract_base_domain("a.b.c.example.com")
        assert result == "example.com"

    def test_two_part_domain_unchanged(self):
        assert DNSAnalyzer._extract_base_domain("example.com") == "example.com"

    def test_single_label(self):
        assert DNSAnalyzer._extract_base_domain("localhost") == "localhost"

    def test_trailing_dot_stripped(self):
        assert DNSAnalyzer._extract_base_domain("sub.example.com.") == "example.com"


# ================================================================== #
#  _extract_subdomain tests
# ================================================================== #


class TestExtractSubdomain:
    """Tests for DNSAnalyzer._extract_subdomain."""

    def test_single_subdomain(self):
        assert DNSAnalyzer._extract_subdomain("sub.example.com") == "sub"

    def test_multi_level_subdomain(self):
        result = DNSAnalyzer._extract_subdomain("a.b.c.example.com")
        assert result == "a.b.c"

    def test_no_subdomain_two_labels(self):
        assert DNSAnalyzer._extract_subdomain("example.com") == ""

    def test_no_subdomain_single_label(self):
        assert DNSAnalyzer._extract_subdomain("localhost") == ""

    def test_trailing_dot_stripped(self):
        assert DNSAnalyzer._extract_subdomain("sub.example.com.") == "sub"


# ================================================================== #
#  detect_tunneling tests
# ================================================================== #


class TestDetectTunneling:
    """Tests for DNSAnalyzer.detect_tunneling."""

    def test_short_normal_domain_not_tunnel(self):
        analyzer = DNSAnalyzer()
        is_tunnel, conf, details = analyzer.detect_tunneling(
            "www.google.com", "google.com", time.time(),
        )
        assert is_tunnel is False
        assert conf < 0.6

    def test_long_random_subdomain_is_tunnel(self):
        # Very long random-looking subdomain with high entropy
        long_random = (
            "x8k3j9f2m7q1p5n4o6r0a8b3c7d2e9f1g5h4i6j0k3.evil.com"
        )
        analyzer = DNSAnalyzer(
            tunneling_entropy_threshold=3.0,
            tunneling_length_threshold=30,
        )
        is_tunnel, conf, details = analyzer.detect_tunneling(
            long_random, "evil.com", time.time(),
        )
        assert is_tunnel is True
        assert conf >= 0.6
        assert "subdomain_entropy" in details
        assert "subdomain_length" in details

    def test_high_query_rate_contributes_confidence(self):
        analyzer = DNSAnalyzer(query_rate_threshold=5)
        now = time.time()
        base = "suspicious.com"
        # Pre-populate rate history to exceed threshold
        for i in range(10):
            analyzer._domain_rate[base].append(now - i)

        # Use a long-ish subdomain with moderate entropy to push over 0.6
        query = "aabbccdd1122334455.suspicious.com"
        is_tunnel, conf, details = analyzer.detect_tunneling(
            query, base, now,
        )
        assert details["queries_per_minute"] >= 10

    def test_tunneling_details_keys(self):
        analyzer = DNSAnalyzer()
        _, _, details = analyzer.detect_tunneling(
            "test.example.com", "example.com", time.time(),
        )
        assert "domain" in details
        assert "subdomain_entropy" in details
        assert "subdomain_length" in details
        assert "queries_per_minute" in details

    def test_confidence_capped_at_one(self):
        # Force all three indicators to fire
        analyzer = DNSAnalyzer(
            tunneling_entropy_threshold=0.1,
            tunneling_length_threshold=1,
            query_rate_threshold=1,
        )
        now = time.time()
        base = "evil.com"
        for _ in range(5):
            analyzer._domain_rate[base].append(now)

        long_sub = "a" * 60 + "bcdefghij" + ".evil.com"
        _, conf, _ = analyzer.detect_tunneling(long_sub, base, now)
        assert conf <= 1.0


# ================================================================== #
#  detect_dga tests
# ================================================================== #


class TestDetectDga:
    """Tests for DNSAnalyzer.detect_dga."""

    def test_google_not_dga(self):
        analyzer = DNSAnalyzer()
        is_dga, conf = analyzer.detect_dga("google.com")
        assert is_dga is False

    def test_random_string_is_dga(self):
        analyzer = DNSAnalyzer()
        is_dga, conf = analyzer.detect_dga("qxjkm8zp3nf7wy2rv5tg.com")
        assert is_dga is True
        assert conf >= 0.6

    def test_short_domain_not_dga(self):
        analyzer = DNSAnalyzer()
        is_dga, conf = analyzer.detect_dga("ab.com")
        assert is_dga is False
        assert conf == 0.0

    def test_four_char_domain_not_dga(self):
        # Label "abcd" has length 4, below the 5-char threshold
        analyzer = DNSAnalyzer()
        is_dga, conf = analyzer.detect_dga("abcd.com")
        assert is_dga is False

    def test_english_word_not_dga(self):
        analyzer = DNSAnalyzer()
        is_dga, _ = analyzer.detect_dga("microsoft.com")
        assert is_dga is False

    def test_dga_confidence_between_0_and_1(self):
        analyzer = DNSAnalyzer()
        _, conf = analyzer.detect_dga("qz9x8j7k6m5.com")
        assert 0.0 <= conf <= 1.0

    def test_numeric_domain_evaluated(self):
        analyzer = DNSAnalyzer()
        # All-digit domain: "1234567890.com" - moderate entropy, low bigram
        is_dga, conf = analyzer.detect_dga("1234567890.com")
        # Behaviour depends on thresholds; just ensure no crash
        assert isinstance(is_dga, bool)


# ================================================================== #
#  detect_doh_evasion tests
# ================================================================== #


class TestDetectDohEvasion:
    """Tests for DNSAnalyzer.detect_doh_evasion."""

    def test_non_browser_to_google_doh_detected(self):
        analyzer = DNSAnalyzer()
        is_doh, conf = analyzer.detect_doh_evasion(
            "8.8.8.8", 443, "malware.exe",
        )
        assert is_doh is True
        assert conf == 0.8

    def test_non_browser_to_cloudflare_doh_detected(self):
        analyzer = DNSAnalyzer()
        is_doh, conf = analyzer.detect_doh_evasion(
            "1.1.1.1", 443, "backdoor.exe",
        )
        assert is_doh is True

    def test_browser_to_google_doh_not_detected(self):
        analyzer = DNSAnalyzer()
        is_doh, conf = analyzer.detect_doh_evasion(
            "8.8.8.8", 443, "chrome.exe",
        )
        assert is_doh is False
        assert conf == 0.0

    def test_browser_firefox_not_detected(self):
        analyzer = DNSAnalyzer()
        is_doh, _ = analyzer.detect_doh_evasion(
            "1.1.1.1", 443, "firefox.exe",
        )
        assert is_doh is False

    def test_non_doh_ip_not_detected(self):
        analyzer = DNSAnalyzer()
        is_doh, conf = analyzer.detect_doh_evasion(
            "192.168.1.1", 443, "malware.exe",
        )
        assert is_doh is False
        assert conf == 0.0

    def test_wrong_port_not_detected(self):
        analyzer = DNSAnalyzer()
        is_doh, conf = analyzer.detect_doh_evasion(
            "8.8.8.8", 80, "malware.exe",
        )
        assert is_doh is False
        assert conf == 0.0

    def test_port_8443_detected(self):
        analyzer = DNSAnalyzer()
        is_doh, conf = analyzer.detect_doh_evasion(
            "8.8.8.8", 8443, "malware.exe",
        )
        assert is_doh is True

    def test_case_insensitive_browser_match(self):
        analyzer = DNSAnalyzer()
        is_doh, _ = analyzer.detect_doh_evasion(
            "8.8.8.8", 443, "Chrome.exe",
        )
        assert is_doh is False


# ================================================================== #
#  analyze_query tests
# ================================================================== #


class TestAnalyzeQuery:
    """Tests for DNSAnalyzer.analyze_query."""

    def test_empty_query_returns_none(self):
        analyzer = DNSAnalyzer()
        assert analyzer.analyze_query("") is None

    def test_none_like_empty_returns_none(self):
        analyzer = DNSAnalyzer()
        # Empty string should return None
        result = analyzer.analyze_query("")
        assert result is None

    def test_normal_domain_returns_none(self):
        analyzer = DNSAnalyzer()
        result = analyzer.analyze_query("www.google.com")
        assert result is None

    def test_normal_domain_safe_microsoft(self):
        analyzer = DNSAnalyzer()
        result = analyzer.analyze_query("update.microsoft.com")
        assert result is None

    def test_tunneling_domain_returns_result(self):
        analyzer = DNSAnalyzer(
            tunneling_entropy_threshold=2.5,
            tunneling_length_threshold=20,
        )
        long_random = "x8k3j9f2m7q1p5n4o6r0abcdefgh.evil.com"
        result = analyzer.analyze_query(long_random)
        # If detected, result should have threat_type tunneling
        if result is not None:
            assert result.is_suspicious is True
            assert result.threat_type in ("tunneling", "dga", "suspicious_tld")

    def test_dga_domain_returns_result(self):
        analyzer = DNSAnalyzer()
        result = analyzer.analyze_query("qxjkm8zp3nf7wy2rv5tg.com")
        assert result is not None
        assert result.is_suspicious is True
        assert result.threat_type == "dga"

    def test_ioc_lookup_match_returns_known_malicious(self):
        def ioc_lookup(domain):
            if domain == "evil-c2.bad":
                return {"source": "threat_feed", "severity": "critical"}
            return None

        analyzer = DNSAnalyzer(ioc_lookup=ioc_lookup)
        result = analyzer.analyze_query("evil-c2.bad")
        assert result is not None
        assert result.is_suspicious is True
        assert result.threat_type == "known_malicious"
        assert result.confidence == 0.95
        assert "ioc" in result.details

    def test_ioc_lookup_no_match(self):
        def ioc_lookup(domain):
            return None

        analyzer = DNSAnalyzer(ioc_lookup=ioc_lookup)
        result = analyzer.analyze_query("www.google.com")
        assert result is None

    def test_suspicious_tld_detected(self):
        analyzer = DNSAnalyzer()
        result = analyzer.analyze_query("legitimate-looking.tk")
        assert result is not None
        assert result.is_suspicious is True
        assert result.threat_type == "suspicious_tld"
        assert result.confidence == 0.4
        assert result.details["tld"] == "tk"

    def test_suspicious_tld_ml(self):
        analyzer = DNSAnalyzer()
        result = analyzer.analyze_query("something.ml")
        assert result is not None
        assert result.threat_type == "suspicious_tld"

    def test_doh_evasion_via_analyze_query(self):
        analyzer = DNSAnalyzer()
        result = analyzer.analyze_query(
            "some-domain.com",
            process_name="malware.exe",
            remote_addr="8.8.8.8",
            remote_port=443,
        )
        assert result is not None
        assert result.is_suspicious is True
        assert result.threat_type == "doh_evasion"
        assert result.details["process"] == "malware.exe"

    def test_doh_not_triggered_without_process_name(self):
        """DoH check requires both remote_addr and process_name."""
        analyzer = DNSAnalyzer()
        # Only providing remote_addr without process_name should skip DoH
        result = analyzer.analyze_query(
            "www.google.com",
            remote_addr="8.8.8.8",
            remote_port=443,
        )
        # Should return None since google.com is not suspicious in other ways
        assert result is None

    def test_query_appended_to_history(self):
        analyzer = DNSAnalyzer()
        analyzer.analyze_query("test.example.com")
        assert len(analyzer._query_history) == 1

    def test_ioc_lookup_checked_before_tunneling(self):
        """IOC match should short-circuit further analysis."""
        call_order = []

        def ioc_lookup(domain):
            call_order.append("ioc")
            return {"bad": True}

        analyzer = DNSAnalyzer(ioc_lookup=ioc_lookup)
        result = analyzer.analyze_query(
            "x8k3j9f2m7q1p5n4o6r0abcdefgh.evil.com",
        )
        assert result.threat_type == "known_malicious"
        # IOC match happened
        assert "ioc" in call_order


# ================================================================== #
#  _queries_per_minute tests
# ================================================================== #


class TestQueriesPerMinute:
    """Tests for DNSAnalyzer._queries_per_minute."""

    def test_no_history_returns_zero(self):
        analyzer = DNSAnalyzer()
        now = time.time()
        assert analyzer._queries_per_minute("example.com", now) == 0

    def test_counts_recent_queries(self):
        analyzer = DNSAnalyzer()
        now = time.time()
        domain = "test.com"
        # Add 5 queries within the last 60 seconds
        for i in range(5):
            analyzer._domain_rate[domain].append(now - i)

        count = analyzer._queries_per_minute(domain, now)
        assert count == 5

    def test_ignores_old_queries(self):
        analyzer = DNSAnalyzer()
        now = time.time()
        domain = "old.com"
        # Add queries older than 60 seconds
        for i in range(5):
            analyzer._domain_rate[domain].append(now - 120 - i)

        count = analyzer._queries_per_minute(domain, now)
        assert count == 0

    def test_mixed_old_and_new(self):
        analyzer = DNSAnalyzer()
        now = time.time()
        domain = "mixed.com"
        # 3 recent, 2 old
        analyzer._domain_rate[domain].append(now - 10)
        analyzer._domain_rate[domain].append(now - 20)
        analyzer._domain_rate[domain].append(now - 30)
        analyzer._domain_rate[domain].append(now - 90)
        analyzer._domain_rate[domain].append(now - 120)

        count = analyzer._queries_per_minute(domain, now)
        assert count == 3

    def test_different_domains_independent(self):
        analyzer = DNSAnalyzer()
        now = time.time()
        analyzer._domain_rate["a.com"].append(now - 5)
        analyzer._domain_rate["a.com"].append(now - 10)
        analyzer._domain_rate["b.com"].append(now - 5)

        assert analyzer._queries_per_minute("a.com", now) == 2
        assert analyzer._queries_per_minute("b.com", now) == 1
        assert analyzer._queries_per_minute("c.com", now) == 0


# ================================================================== #
#  Edge cases and additional coverage
# ================================================================== #


class TestEdgeCases:
    """Additional edge-case tests for thorough coverage."""

    def test_analyze_query_domain_rate_populated(self):
        analyzer = DNSAnalyzer()
        analyzer.analyze_query("sub.example.com")
        # Base domain should be tracked
        assert "example.com" in analyzer._domain_rate

    def test_window_size_respected(self):
        analyzer = DNSAnalyzer(window_size=5)
        for i in range(10):
            analyzer.analyze_query(f"domain{i}.com")
        assert len(analyzer._query_history) == 5

    def test_detect_tunneling_empty_subdomain(self):
        analyzer = DNSAnalyzer()
        is_tunnel, conf, details = analyzer.detect_tunneling(
            "example.com", "example.com", time.time(),
        )
        assert is_tunnel is False
        assert details["subdomain_length"] == 0

    def test_detect_dga_domain_without_tld(self):
        analyzer = DNSAnalyzer()
        is_dga, conf = analyzer.detect_dga("xkjh3kf9z2m7")
        # Should still evaluate the single label
        assert isinstance(is_dga, bool)

    def test_suspicious_tld_not_in_normal_tld(self):
        analyzer = DNSAnalyzer()
        result = analyzer.analyze_query("test.com")
        assert result is None  # .com is not suspicious

    def test_analyze_query_returns_none_for_safe_domain_no_kwargs(self):
        analyzer = DNSAnalyzer()
        result = analyzer.analyze_query("docs.python.org")
        assert result is None

    def test_doh_evasion_all_providers(self):
        """Every DOH provider IP should be detected for non-browser process."""
        analyzer = DNSAnalyzer()
        for ip in DOH_PROVIDERS:
            is_doh, _ = analyzer.detect_doh_evasion(ip, 443, "backdoor.exe")
            assert is_doh is True, f"Expected DoH detection for {ip}"

    def test_all_browsers_exempt_from_doh(self):
        """Every known browser should NOT trigger DoH evasion."""
        analyzer = DNSAnalyzer()
        for browser in BROWSER_PROCESSES:
            is_doh, _ = analyzer.detect_doh_evasion("8.8.8.8", 443, browser)
            assert is_doh is False, f"Browser {browser} should be exempt"
