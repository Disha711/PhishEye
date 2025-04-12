import re
import tldextract
import socket
import requests
from urllib.parse import urlparse

FEATURE_NAMES = [
    'having_IP_Address', 'URL_Length', 'Shortining_Service', 'having_At_Symbol',
    'double_slash_redirecting', 'Prefix_Suffix', 'having_Sub_Domain', 'SSLfinal_State',
    'Domain_registeration_length', 'Favicon', 'port', 'HTTPS_token', 'Request_URL',
    'URL_of_Anchor', 'Links_in_tags', 'SFH', 'Submitting_to_email', 'Abnormal_URL',
    'Redirect', 'on_mouseover', 'RightClick', 'popUpWidnow', 'Iframe', 'age_of_domain',
    'DNSRecord', 'web_traffic', 'Page_Rank', 'Google_Index', 'Links_pointing_to_page',
    'Statistical_report'
]

def extract_features(url):
    try:
        domain_info = tldextract.extract(url)
        subdomain = domain_info.subdomain
        domain = domain_info.domain

        shortening_services = ["bit.ly", "goo.gl", "tinyurl", "ow.ly", "t.co", "is.gd", "buff.ly"]
        
        # Extracting features
        features = {
            "having_IP_Address": 1 if re.search(r'\d+\.\d+\.\d+\.\d+', url) else 0,
            "URL_Length": len(url),
            "Shortining_Service": 1 if any(service in url for service in shortening_services) else 0,
            "having_At_Symbol": 1 if "@" in url else 0,
            "double_slash_redirecting": 1 if url[7:].count("//") > 0 else 0,
            "Prefix_Suffix": 1 if "-" in domain else 0,
            "having_Sub_Domain": len(subdomain.split(".")) if subdomain else 0,
            "SSLfinal_State": 1 if url.startswith("https") else 0,
            "Domain_registeration_length": get_domain_registration_length(domain),
            "Favicon": 1 if check_favicon(url) else 0,
            "port": extract_port(url),
            "HTTPS_token": 1 if "https" in domain else 0,
            "Request_URL": extract_request_url(url),
            "URL_of_Anchor": extract_anchor_url(url),
            "Links_in_tags": count_links_in_tags(url),
            "SFH": extract_sfh(url),
            "Submitting_to_email": 1 if "mailto:" in url else 0,
            "Abnormal_URL": 1 if check_abnormal_url(url) else 0,
            "Redirect": check_redirect(url),
            "on_mouseover": check_on_mouseover(url),
            "RightClick": check_right_click(url),
            "popUpWidnow": check_pop_up_window(url),
            "Iframe": check_iframe(url),
            "age_of_domain": get_domain_age(domain),
            "DNSRecord": check_dns_record(domain),
            "web_traffic": estimate_traffic(domain),
            "Page_Rank": get_page_rank(domain),
            "Google_Index": check_google_index(domain),
            "Links_pointing_to_page": count_links_pointing_to_page(url),
            "Statistical_report": get_statistical_report(url)
        }

        return [features[feature] for feature in FEATURE_NAMES]

    except Exception as e:
        print(f"Feature extraction failed: {e}")
        return None

def get_domain_registration_length(domain):
    # Placeholder for actual logic (e.g., WHOIS query)
    return 1  # Placeholder value

def check_favicon(url):
    try:
        response = requests.get(url + "/favicon.ico")
        return response.status_code == 200
    except requests.exceptions.RequestException:
        return False

def extract_port(url):
    parsed_url = urlparse(url)
    return parsed_url.port if parsed_url.port else 0

def extract_request_url(url):
    # Placeholder logic
    return 1  # Placeholder value

def extract_anchor_url(url):
    # Placeholder logic
    return 1  # Placeholder value

def count_links_in_tags(url):
    # Placeholder logic
    return 1  # Placeholder value

def extract_sfh(url):
    # Placeholder logic
    return 1  # Placeholder value

def check_abnormal_url(url):
    # Placeholder logic
    return False  # Placeholder value

def check_redirect(url):
    # Placeholder logic
    return False  # Placeholder value

def check_on_mouseover(url):
    # Placeholder logic
    return True  # Placeholder value

def check_right_click(url):
    # Placeholder logic
    return True  # Placeholder value

def check_pop_up_window(url):
    # Placeholder logic
    return True  # Placeholder value

def check_iframe(url):
    # Placeholder logic
    return True  # Placeholder value

def get_domain_age(domain):
    # Placeholder logic
    return 1  # Placeholder value

def check_dns_record(domain):
    # Placeholder logic
    return True  # Placeholder value

def estimate_traffic(domain):
    # Placeholder logic
    return 1  # Placeholder value

def get_page_rank(domain):
    # Placeholder logic
    return 1  # Placeholder value

def check_google_index(domain):
    # Placeholder logic
    return True  # Placeholder value

def count_links_pointing_to_page(url):
    # Placeholder logic
    return 1  # Placeholder value

def get_statistical_report(url):
    # Placeholder logic
    return 1  # Placeholder value
