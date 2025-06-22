import requests
import re
import yaml
from concurrent.futures import ThreadPoolExecutor

# Load API keys from YAML
def load_keys():
    with open("config/settings.yaml", "r") as f:
        return yaml.safe_load(f)["api_keys"]

keys = load_keys()

# IOC type detector
def detect_type(ioc: str) -> str:
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ioc):
        return "IP"
    elif re.match(r"^[a-fA-F0-9]{32,64}$", ioc):
        return "Hash"
    elif "." in ioc:
        return "Domain"
    return "Unknown"

# Enrich with OTX
def enrich_otx(ioc: str) -> dict:
    otx_key = keys["otx"]
    ioc_type = detect_type(ioc).lower()
    if ioc_type == "hash":
        ioc_type = "file"
    url = f"https://otx.alienvault.com/api/v1/indicators/{ioc_type}/{ioc}/general"
    headers = {"X-OTX-API-KEY": otx_key}
    try:
        resp = requests.get(url, headers=headers, timeout=10)
        data = resp.json()
        
        # Collect pulse tags
        pulse_tags = []
        pulses = data.get("pulse_info", {}).get("pulses", [])
        for pulse in pulses:
            tags = pulse.get("tags", [])
            pulse_tags.extend(tags)
        
        return {
            "OTX_Pulse_Count": data.get("pulse_info", {}).get("count", 0),
            "OTX_Malicious": bool(data.get("pulse_info", {}).get("count", 0)),
            "OTX_Tags": ", ".join(set(pulse_tags)) if pulse_tags else "-",
            "OTX_Country": data.get("country_name", "-"),
        }
    except:
        return {"OTX_Pulse_Count": "-", "OTX_Malicious": "-", "OTX_Tags": "-", "OTX_Country": "-"}

# Enrich with VirusTotal
def enrich_vt(ioc: str) -> dict:
    vt_key = keys["virustotal"]
    headers = {"x-apikey": vt_key}
    url = f"https://www.virustotal.com/api/v3/search?query={ioc}"
    try:
        resp = requests.get(url, headers=headers, timeout=10)
        data = resp.json()
        
        if not data.get("data"):
            return {"VT_Malicious": 0, "VT_Suspicious": 0, "VT_Tags": "-"}

        attributes = data.get("data", [{}])[0].get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})
        
        vt_tags = []
        
        # Use popular_threat_classification for better tags if available (files, domains)
        classification = attributes.get("popular_threat_classification")
        if classification and classification.get("suggested_threat_label"):
            vt_tags.append(classification.get("suggested_threat_label"))
            for category in classification.get("popular_threat_category", []):
                vt_tags.append(category.get("value"))
            for name in classification.get("popular_threat_name", []):
                vt_tags.append(name.get("value"))

        # Fallback to last_analysis_results if the above is not available
        if not vt_tags:
            last_analysis_results = attributes.get("last_analysis_results", {})
            for engine, result in last_analysis_results.items():
                res = result.get("result")
                if res and res not in ["clean", "unrated", "timeout"]:
                    vt_tags.append(res)
        
        return {
            "VT_Malicious": stats.get("malicious", 0),
            "VT_Suspicious": stats.get("suspicious", 0),
            "VT_Tags": ", ".join(set(vt_tags)) if vt_tags else "-",
        }
    except:
        return {"VT_Malicious": "-", "VT_Suspicious": "-", "VT_Tags": "-"}
    
# Enrich with GreyNoise
def enrich_greynoise(ioc: str) -> dict:
    if detect_type(ioc) != "IP":
        return {"GN_Classification": "-", "GN_Name": "-", "GN_Tags": "-"}
    
    try:
        gn_key = keys["greynoise"]
        headers = {"key": gn_key, "accept": "application/json"}
        url = f"https://api.greynoise.io/v3/community/{ioc}"
        resp = requests.get(url, headers=headers, timeout=10)

        if resp.status_code == 404:
            return {"GN_Classification": "unknown", "GN_Name": "-", "GN_Tags": "-"}

        data = resp.json()
        tags = data.get("tags", [])
        return {
            "GN_Classification": data.get("classification", "-"),
            "GN_Name": data.get("name", "-"),
            "GN_Tags": ", ".join(tags) if tags else "-",
        }
    except:
        return {"GN_Classification": "error", "GN_Name": "-", "GN_Tags": "-"}

# Enrich with IPinfo
def enrich_ipinfo(ioc: str) -> dict:
    if detect_type(ioc) != "IP":
        return {"IP_Country": "-", "IP_ASN": "-"}
    
    try:
        # IPinfo token is optional for basic lookups
        ipinfo_key = keys.get("ipinfo")
        headers = {}
        if ipinfo_key:
            headers["Authorization"] = f"Bearer {ipinfo_key}"

        url = f"https://ipinfo.io/{ioc}/json"
        resp = requests.get(url, headers=headers, timeout=10)
        data = resp.json()
        
        return {
            "IP_Country": data.get("country", "-"),
            "IP_ASN": data.get("org", "-"),
        }
    except:
        return {"IP_Country": "-", "IP_ASN": "-"}