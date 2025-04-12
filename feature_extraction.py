import re
import socket
import whois
import requests
import tldextract
from datetime import datetime
from urllib.parse import urlparse

def extract_features(url):
    try:
        features = []

        # Extract domain info
        parsed_url = urlparse(url)
        hostname = parsed_url.netloc
        ext = tldextract.extract(url)
        domain = ext.domain + '.' + ext.suffix
        subdomain = ext.subdomain

        # Feature 1: having_IP_Address
        try:
            socket.inet_aton(hostname)
            features.append(1)
        except:
            features.append(0)

        # Feature 2: URL_Length
        length = len(url)
        features.append(1 if length < 54 else 2 if length <= 75 else 3)

        # Feature 3: Shortining_Service
        shortening_services = r"(bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|yfrog\.com|migre\.me|ff\.im|tiny\.cc)"
        features.append(1 if re.search(shortening_services, url) else 0)

        # Feature 4: having_At_Symbol
        features.append(1 if "@" in url else 0)

        # Feature 5: double_slash_redirecting
        features.append(1 if "//" in url[7:] else 0)

        # Feature 6: Prefix_Suffix
        features.append(1 if "-" in hostname else 0)

        # Feature 7: having_Sub_Domain
        dot_count = subdomain.count(".")
        features.append(1 if dot_count <= 1 else 2)

        # Feature 8: SSLfinal_State
        features.append(1 if url.startswith("https") else 0)

        # Feature 9: Domain_registeration_length
        try:
            w = whois.whois(domain)
            if w.expiration_date and w.creation_date:
                exp = w.expiration_date if isinstance(w.expiration_date, datetime) else w.expiration_date[0]
                cre = w.creation_date if isinstance(w.creation_date, datetime) else w.creation_date[0]
                age = (exp - cre).days
                features.append(1 if age > 365 else 0)
            else:
                features.append(0)
        except:
            features.append(0)

        # Feature 10: Favicon
        features.append(1 if domain in url else 0)

        # Feature 11: port
        features.append(1 if ':' in hostname else 0)

        # Feature 12: HTTPS_token
        features.append(1 if 'https' in domain else 0)

        # Request-based features (require page fetch)
        try:
            response = requests.get(url, timeout=5)
            content = response.text
        except:
            content = ''

        # Feature 13: Request_URL
        features.append(1 if domain in content else 0)

        # Feature 14: URL_of_Anchor
        anchor_tags = re.findall(r'<a\s+(?:[^>]*?\s+)?href="([^"]*)"', content)
        null_links = [link for link in anchor_tags if link.startswith('#') or not link.startswith('http')]
        percent = len(null_links) / len(anchor_tags) if anchor_tags else 0
        features.append(1 if percent < 0.31 else 0)

        # Feature 15: Links_in_tags
        meta_links = re.findall(r'<meta[^>]+content="[^"]*http[^"]*"', content)
        script_links = re.findall(r'<script[^>]+src="http[^"]*"', content)
        percent = len(meta_links + script_links) / (len(anchor_tags) + 1)
        features.append(1 if percent < 0.25 else 0)

        # Feature 16: SFH
        sfh_match = re.search(r'<form[^>]+action="([^"]*)"', content)
        if sfh_match:
            form_action = sfh_match.group(1)
            if form_action == "" or form_action == "about:blank":
                features.append(1)
            elif domain not in form_action:
                features.append(1)
            else:
                features.append(0)
        else:
            features.append(0)

        # Feature 17: Submitting_to_email
        features.append(1 if "mailto:" in content else 0)

        # Feature 18: Abnormal_URL
        try:
            whois_domain = whois.whois(domain).domain_name
            features.append(0 if whois_domain else 1)
        except:
            features.append(1)

        # Feature 19: Redirect
        features.append(1 if len(response.history) >= 2 else 0)

        # Feature 20: on_mouseover
        features.append(1 if "onmouseover" in content else 0)

        # Feature 21: RightClick
        features.append(1 if "event.button==2" in content else 0)

        # Feature 22: popUpWidnow
        features.append(1 if "alert(" in content else 0)

        # Feature 23: Iframe
        features.append(1 if "<iframe" in content else 0)

        # Feature 24: age_of_domain
        try:
            creation = whois.whois(domain).creation_date
            if isinstance(creation, list):
                creation = creation[0]
            age = (datetime.now() - creation).days if creation else 0
            features.append(1 if age > 180 else 0)
        except:
            features.append(0)

        # Feature 25: DNSRecord
        try:
            whois.whois(domain)
            features.append(1)
        except:
            features.append(0)

        # Feature 26: web_traffic (you can replace this with real Alexa/SimilarWeb API later)
        features.append(1)  # Assume legit for now

        # Feature 27: Page_Rank (can be improved)
        features.append(1)  # Assume legit

        # Feature 28: Google_Index
        features.append(1)  # Assume indexed

        # Feature 29: Links_pointing_to_page
        features.append(1)  # Assume not suspicious

        # Feature 30: Statistical_report
        features.append(1)  # Assume not in blacklist

        return features

    except Exception as e:
        print("Feature extraction error:", e)
        return [0] * 31
