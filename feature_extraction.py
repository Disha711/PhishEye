
import re
import tldextract

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

        features = {
            "having_IP_Address": 1 if re.search(r'\d+\.\d+\.\d+\.\d+', url) else 0,
            "URL_Length": 1 if len(url) < 54 else 2 if len(url) < 75 else 3,
            "Shortining_Service": 1 if any(service in url for service in shortening_services) else 0,
            "having_At_Symbol": 1 if "@" in url else 0,
            "double_slash_redirecting": 1 if re.search(r"https?://.*//", url[8:]) else 0,
            "Prefix_Suffix": 1 if "-" in domain else 0,
            "having_Sub_Domain": 1 if subdomain.count('.') <= 1 else 2,
            "SSLfinal_State": 1 if url.startswith("https") else 0,
            "Domain_registeration_length": 1,  # Placeholder, to be replaced with real data
            "Favicon": 1,  # Placeholder
            "port": 0,  # Placeholder
            "HTTPS_token": 0,  # Placeholder
            "Request_URL": 1,  # Placeholder
            "URL_of_Anchor": 1,  # Placeholder
            "Links_in_tags": 1,  # Placeholder
            "SFH": 1,  # Placeholder
            "Submitting_to_email": 0,  # Placeholder
            "Abnormal_URL": 0,  # Placeholder
            "Redirect": 0,  # Placeholder
            "on_mouseover": 0,  # Placeholder
            "RightClick": 0,  # Placeholder
            "popUpWidnow": 0,  # Placeholder
            "Iframe": 0,  # Placeholder
            "age_of_domain": 1,  # Placeholder
            "DNSRecord": 1,  # Placeholder
            "web_traffic": 1,  # Placeholder
            "Page_Rank": 1,  # Placeholder
            "Google_Index": 1,  # Placeholder
            "Links_pointing_to_page": 1,  # Placeholder
            "Statistical_report": 1  # Placeholder
        }

        return list(features.values())
    except Exception as e:
        print(f"Error extracting features: {e}")
        return [0]*len(FEATURE_NAMES)
