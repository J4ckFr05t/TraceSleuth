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
        return {
            "OTX_Pulse_Count": data.get("pulse_info", {}).get("count", 0),
            "OTX_Malicious": bool(data.get("pulse_info", {}).get("count", 0)),
        }
    except:
        return {"OTX_Pulse_Count": "-", "OTX_Malicious": "-"}

# Enrich with VirusTotal
def enrich_vt(ioc: str) -> dict:
    vt_key = keys["virustotal"]
    headers = {"x-apikey": vt_key}
    url = f"https://www.virustotal.com/api/v3/search?query={ioc}"
    try:
        resp = requests.get(url, headers=headers, timeout=10)
        data = resp.json()
        stats = data.get("data", [{}])[0].get("attributes", {}).get("last_analysis_stats", {})
        return {
            "VT_Malicious": stats.get("malicious", 0),
            "VT_Suspicious": stats.get("suspicious", 0),
        }
    except:
        return {"VT_Malicious": "-", "VT_Suspicious": "-"}