"""
Feature Extractor for Phishing URL Detection
Extracts 42 URL-based features matching the Kaggle dataset
"""

import re
from urllib.parse import urlparse
import tldextract
import math

class PhishingFeatureExtractor:

    def __init__(self):
        self.shortening_services = [
            'bit.ly', 'goo.gl', 'tinyurl.com', 't.co', 'ow.ly',
            'is.gd', 'buff.ly', 'adf.ly', 'bl.ink', 'lnkd.in'
        ]

        self.common_tlds = [
            '.com', '.net', '.org', '.edu', '.gov', '.mil',
            '.co', '.uk', '.de', '.fr', '.it', '.es'
        ]
    def extract_features(self, url):
        """
        Extract all 42 URL-based features
        Returns: dictionary of features
        """
        try:
            # Clean URL
            url = url.strip()

            # Parse URL
            parsed = urlparse(url)
            extracted = tldextract.extract(url)

            features = {}

            # ============================================================
            # LENGTH FEATURES
            # ============================================================
            features['length_url'] = len(url)
            features['length_hostname'] = len(parsed.netloc)

            # ============================================================
            # IP ADDRESS CHECK
            # ============================================================
            ip_pattern = re.compile(r'(\d{1,3}\.){3}\d{1,3}')
            features['ip'] = 1 if ip_pattern.search(parsed.netloc) else 0

            # ============================================================
            # CHARACTER COUNTS
            # ============================================================
            features['nb_dots'] = url.count('.')
            features['nb_hyphens'] = url.count('-')
            features['nb_at'] = url.count('@')
            features['nb_qm'] = url.count('?')
            features['nb_and'] = url.count('&')
            features['nb_or'] = url.count('|')
            features['nb_eq'] = url.count('=')
            features['nb_underscore'] = url.count('_')
            features['nb_tilde'] = url.count('~')
            features['nb_percent'] = url.count('%')
            features['nb_slash'] = url.count('/')
            features['nb_star'] = url.count('*')
            features['nb_colon'] = url.count(':')
            features['nb_comma'] = url.count(',')
            features['nb_semicolumn'] = url.count(';')
            features['nb_dollar'] = url.count('$')
            features['nb_space'] = url.count(' ')

            # ============================================================
            # DOMAIN-SPECIFIC COUNTS
            # ============================================================
            features['nb_www'] = url.lower().count('www')

            # FIX: Count .com only in domain/path, not in all URL
            # Only count if it's actually a .com TLD
            features['nb_com'] = 1 if extracted.suffix == 'com' else 0

            # FIX: Count // excluding the protocol
            # Remove protocol first, then count
            url_without_protocol = url.split('://', 1)[-1] if '://' in url else url
            features['nb_dslash'] = url_without_protocol.count('//')

            # ============================================================
            # PROTOCOL & PATH CHECKS
            # ============================================================
            path = parsed.path + parsed.query + parsed.fragment
            features['http_in_path'] = 1 if 'http' in path.lower() else 0

            # FIX: https_token should check if 'https' appears in non-protocol parts
            # even when using http protocol (suspicious)
            features['https_token'] = 1 if 'https' in path.lower() else 0

            # ============================================================
            # DIGIT RATIOS
            # ============================================================
            digits_url = sum(c.isdigit() for c in url)
            digits_host = sum(c.isdigit() for c in parsed.netloc)

            features['ratio_digits_url'] = digits_url / len(url) if len(url) > 0 else 0
            features['ratio_digits_host'] = digits_host / len(parsed.netloc) if len(parsed.netloc) > 0 else 0

            # ============================================================
            # SPECIAL URL CHARACTERISTICS
            # ============================================================
            # Punycode (internationalized domain)
            features['punycode'] = 1 if 'xn--' in url.lower() else 0
            features['port'] = 1 if parsed.port is not None else 0

            features['tld_in_path'] = 1 if any(tld in path.lower() for tld in self.common_tlds) else 0
            features['tld_in_subdomain'] = 1 if any(tld in extracted.subdomain.lower() for tld in self.common_tlds) else 0

            # ============================================================
            # SUBDOMAIN ANALYSIS
            # ============================================================
            if extracted.subdomain:
                # Count dots in subdomain + 1 (or just count parts)
                # The dataset likely counts differently
                subdomain_parts = extracted.subdomain.split('.')
                features['nb_subdomains'] = len(subdomain_parts)
            else:
                features['nb_subdomains'] = 0

            features['abnormal_subdomain'] = 1 if features['nb_subdomains'] > 3 else 0

            # ============================================================
            # DOMAIN CHARACTERISTICS
            # ============================================================
            # Prefix/suffix with hyphen
            features['prefix_suffix'] = 1 if '-' in extracted.domain else 0

            # URL shortening service
            features['shortening_service'] = 1 if any(
                shortener in url.lower() for shortener in self.shortening_services
            ) else 0

            # Suspicious file extensions in path
            suspicious_extensions = ['.exe', '.zip', '.rar', '.scr', '.bat', '.cmd']
            features['path_extension'] = 1 if any(ext in path.lower() for ext in suspicious_extensions) else 0

            # ============================================================
            # WORD-BASED FEATURES
            # ============================================================
            # Extract words (alphanumeric sequences)
            words_host = re.findall(r'\w+', parsed.netloc)
            words_path = re.findall(r'\w+', path)

            if words_host:
                word_lengths_host = [len(w) for w in words_host]
                features['shortest_word_host'] = min(word_lengths_host)
                features['longest_word_host'] = max(word_lengths_host)
                features['avg_word_host'] = sum(word_lengths_host) / len(word_lengths_host)
            else:
                features['shortest_word_host'] = 0
                features['longest_word_host'] = 0
                features['avg_word_host'] = 0

            if words_path:
                word_lengths_path = [len(w) for w in words_path]
                features['shortest_word_path'] = min(word_lengths_path)
                features['longest_word_path'] = max(word_lengths_path)
                features['avg_word_path'] = sum(word_lengths_path) / len(word_lengths_path)
            else:
                features['shortest_word_path'] = 0
                features['longest_word_path'] = 0
                features['avg_word_path'] = 0

            return features

        except Exception as e:
            print(f"Error extracting features from URL: {e}")
            return None

    def get_feature_names(self):
        """Return list of feature names in correct order"""
        return [
            'length_url', 'length_hostname', 'ip', 'nb_dots', 'nb_hyphens',
            'nb_at', 'nb_qm', 'nb_and', 'nb_or', 'nb_eq', 'nb_underscore',
            'nb_tilde', 'nb_percent', 'nb_slash', 'nb_star', 'nb_colon',
            'nb_comma', 'nb_semicolumn', 'nb_dollar', 'nb_space', 'nb_www',
            'nb_com', 'nb_dslash', 'http_in_path', 'https_token',
            'ratio_digits_url', 'ratio_digits_host', 'punycode', 'port',
            'tld_in_path', 'tld_in_subdomain', 'abnormal_subdomain',
            'nb_subdomains', 'prefix_suffix', 'shortening_service',
            'path_extension', 'shortest_word_host', 'shortest_word_path',
            'longest_word_host', 'longest_word_path', 'avg_word_host',
            'avg_word_path'
        ]


# Testing function
if __name__ == "__main__":
    extractor = PhishingFeatureExtractor()

    # Test URLs
    test_urls = [
        "https://www.google.com",
        "http://192.168.1.1/admin/login.php",
        "http://paypal-verify-account.suspicious-domain.com/update?id=12345",
        "https://bit.ly/abc123"
    ]

    for url in test_urls:
        print(f"\nURL: {url}")
        features = extractor.extract_features(url)
        if features:
            print(f"Features extracted: {len(features)}")
            print(f"Sample: length_url={features['length_url']}, ip={features['ip']}, nb_dots={features['nb_dots']}")
