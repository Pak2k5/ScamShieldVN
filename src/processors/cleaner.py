"""Data cleaning and normalization for ScamShield VN pipeline.

Implements URL normalization and text cleaning as Stage 1 of the processing pipeline.
"""

import re
import unicodedata
from urllib.parse import urlparse, urlunparse, parse_qs, urlencode, quote, unquote

from loguru import logger


class Cleaner:
    """Cleans and normalizes URLs and text content.
    
    URL normalization: lowercase scheme+domain, remove trailing slash,
    remove default ports, sort query params.
    
    Text normalization: NFC Unicode, strip control chars, collapse whitespace,
    preserve Vietnamese diacritical marks.
    """

    # Default ports to remove
    DEFAULT_PORTS = {"http": 80, "https": 443}

    def normalize_url(self, url: str) -> str:
        """Normalize a URL to canonical form.
        
        - Lowercase scheme and domain
        - Remove trailing slashes (path only)
        - Remove default port numbers (80 for http, 443 for https)
        - Sort query parameters alphabetically
        - Decode unnecessary percent-encoding
        
        Args:
            url: Raw URL string.
            
        Returns:
            Normalized URL string.
            
        Raises:
            ValueError: If URL cannot be parsed.
        """
        if not url or not url.strip():
            raise ValueError("Empty URL")

        url = url.strip()
        
        try:
            parsed = urlparse(url)
        except Exception as e:
            raise ValueError(f"Cannot parse URL: {url}") from e

        # Lowercase scheme and netloc (domain)
        scheme = (parsed.scheme or "http").lower()
        netloc = (parsed.netloc or "").lower()

        # Remove default port
        if ":" in netloc:
            host, port_str = netloc.rsplit(":", 1)
            try:
                port = int(port_str)
                if self.DEFAULT_PORTS.get(scheme) == port:
                    netloc = host
            except ValueError:
                pass

        # Normalize path - remove trailing slash (but keep root "/")
        path = parsed.path or "/"
        if path != "/" and path.endswith("/"):
            path = path.rstrip("/")

        # Sort query parameters alphabetically
        query = parsed.query
        if query:
            params = parse_qs(query, keep_blank_values=True)
            sorted_params = sorted(params.items())
            query = urlencode(sorted_params, doseq=True)

        # Reconstruct
        normalized = urlunparse((scheme, netloc, path, parsed.params, query, ""))
        return normalized

    def normalize_text(self, text: str) -> str:
        """Normalize text content while preserving Vietnamese diacritical marks.
        
        - NFC Unicode normalization
        - Strip control characters (Cc, Cf) except newline, tab, carriage return
        - Collapse multiple whitespace into single spaces
        - Preserve Vietnamese accents (ắ, ề, ọ, ũ, ơ, etc.)
        
        Args:
            text: Raw text string.
            
        Returns:
            Normalized text string.
        """
        if not text:
            return ""

        # NFC normalization (canonical decomposition + canonical composition)
        text = unicodedata.normalize("NFC", text)

        # Remove control characters (Cc, Cf) except \n, \t, \r
        cleaned_chars = []
        for char in text:
            cat = unicodedata.category(char)
            if cat in ("Cc", "Cf"):
                if char in ("\n", "\t", "\r"):
                    cleaned_chars.append(char)
                # else: skip control character
            else:
                cleaned_chars.append(char)
        text = "".join(cleaned_chars)

        # Collapse multiple whitespace (spaces, but preserve newlines)
        text = re.sub(r"[^\S\n]+", " ", text)
        
        # Strip leading/trailing whitespace per line
        lines = text.splitlines()
        lines = [line.strip() for line in lines]
        text = "\n".join(lines)
        
        # Strip leading/trailing whitespace overall
        text = text.strip()

        return text

    def compute_url_features(self, url: str) -> dict:
        """Extract URL-based features for analysis.
        
        Returns dict with: domain, tld, url_length, path_length, query_length,
        has_ip_address, has_punycode, has_url_shortener.
        """
        import tldextract
        
        features = {
            "url_length": len(url),
            "has_ip_address": False,
            "has_punycode": False,
            "has_url_shortener": False,
            "domain": None,
            "tld": None,
            "path_length": 0,
            "query_length": 0,
        }
        
        try:
            parsed = urlparse(url)
            ext = tldextract.extract(url)
            
            features["domain"] = ext.registered_domain or parsed.netloc
            features["tld"] = ext.suffix
            features["path_length"] = len(parsed.path)
            features["query_length"] = len(parsed.query)
            
            # Check for IP address in URL
            ip_pattern = re.compile(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")
            if ip_pattern.search(parsed.netloc):
                features["has_ip_address"] = True
            
            # Check for punycode (xn--)
            if "xn--" in parsed.netloc.lower():
                features["has_punycode"] = True
            
            # Check for URL shorteners
            shorteners = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", 
                         "is.gd", "buff.ly", "short.link", "rb.gy"}
            if ext.registered_domain in shorteners:
                features["has_url_shortener"] = True
                
        except Exception:
            pass
        
        return features
