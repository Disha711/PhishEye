import re
import tldextract

def extract_features(url):
    try:
        features = {
            "having_IP_Address": 1 if re.search(r'\d+\.\d+\.\d+\.\d+', url) else 0,
            "URL_Length": len(url),
            "Shortining_Service": 1 if "bit.ly" in url or "tinyurl" in url else 0,
            "having_At_Symbol": 1 if "@" in url else 0,
            "double_slash_redirecting": 1 if "//" in url[7:] else 0,
            "Prefix_Suffix": 1 if "-" in tldextract.extract(url).domain else 0,
            "having_Sub_Domain": url.count('.') - 1,
            "SSLfinal_State": 1 if url.startswith("https") else 0,
            "Domain_registeration_length": 1,  # Placeholder value
            "Favicon": 1,  # Placeholder
            "port": 0,  # Placeholder
            "HTTPS_token": 1 if "https" in tldextract.extract(url).domain else 0,
            "Request_URL": 1,  # Placeholder
            "URL_of_Anchor": 1,  # Placeholder
            "Links_in_tags": 1,  # Placeholder
            "SFH": 1,  # Placeholder
            "Submitting_to_email": 1 if "mailto:" in url else 0,
            "Abnormal_URL": 1,  # Placeholder
            "Redirect": 0,  # Placeholder
            "on_mouseover": 1,  # Placeholder
            "RightClick": 1,  # Placeholder
            "popUpWidnow": 1,  # Placeholder
            "Iframe": 1,  # Placeholder
            "age_of_domain": 1,  # Placeholder
            "DNSRecord": 1,  # Placeholder
            "web_traffic": 1,  # Placeholder
            "Page_Rank": 1,  # Placeholder
            "Google_Index": 1,  # Placeholder
            "Links_pointing_to_page": 1,  # Placeholder
            "Statistical_report": 1  # Placeholder
        }
        return features
    except Exception as e:
        print(f"Feature extraction failed: {e}")
        return None
