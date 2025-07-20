import requests
import re
import yaml
from concurrent.futures import ThreadPoolExecutor
import logging
import json as pyjson

try:
    import streamlit as st
except ImportError:
    st = None

# Setup logging
logger = logging.getLogger("api_calls")
logger.setLevel(logging.INFO)
file_handler = logging.FileHandler("api_calls.log")
file_handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
if not logger.hasHandlers():
    logger.addHandler(file_handler)

def log_api_call(endpoint, headers, params=None, response=None, error=None):
    # Mask API keys in headers
    safe_headers = {k: ("***" if "key" in k.lower() or "auth" in k.lower() else v) for k, v in (headers or {}).items()}
    log_entry = {
        "endpoint": endpoint,
        "headers": safe_headers,
        "params": params,
    }
    if response is not None:
        try:
            log_entry["response"] = response if isinstance(response, str) else pyjson.dumps(response)
        except Exception:
            log_entry["response"] = str(response)
    if error is not None:
        log_entry["error"] = str(error)
    logger.info(pyjson.dumps(log_entry))

def get_keys(keys=None):
    if keys is not None:
        return keys
    if st is not None and hasattr(st, 'session_state') and 'api_keys' in st.session_state:
        return st.session_state['api_keys']
    raise RuntimeError("API keys not set. Please configure them in the UI.")

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
def enrich_otx(ioc: str, keys=None) -> dict:
    keys = get_keys(keys)
    otx_key = keys.get("otx")
    url = f"https://otx.alienvault.com/api/v1/indicators/{detect_type(ioc).lower()}/{ioc}/general"
    headers = {"X-OTX-API-KEY": otx_key or ""}
    if not otx_key:
        log_api_call(url, headers, params=None, error="OTX key missing or empty")
        return {"OTX_Pulse_Count": "-", "OTX_Malicious": "-", "OTX_Tags": "-", "OTX_Country": "-"}
    ioc_type = detect_type(ioc).lower()
    if ioc_type == "hash":
        ioc_type = "file"
    url = f"https://otx.alienvault.com/api/v1/indicators/{ioc_type}/{ioc}/general"
    headers = {"X-OTX-API-KEY": otx_key}
    try:
        resp = requests.get(url, headers=headers, timeout=10)
        data = resp.json()
        log_api_call(url, headers, params=None, response=data)
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
    except Exception as e:
        log_api_call(url, headers, params=None, error=e)
        return {"OTX_Pulse_Count": "-", "OTX_Malicious": "-", "OTX_Tags": "-", "OTX_Country": "-"}

# Enrich with VirusTotal
def enrich_vt(ioc: str, keys=None) -> dict:
    keys = get_keys(keys)
    vt_key = keys.get("virustotal")
    url = f"https://www.virustotal.com/api/v3/search?query={ioc}"
    headers = {"x-apikey": vt_key or ""}
    if not vt_key:
        log_api_call(url, headers, params=None, error="VirusTotal key missing or empty")
        return {"VT_Malicious": "-", "VT_Suspicious": "-", "VT_Tags": "-"}
    try:
        resp = requests.get(url, headers=headers, timeout=10)
        data = resp.json()
        log_api_call(url, headers, params=None, response=data)
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
    except Exception as e:
        log_api_call(url, headers, params=None, error=e)
        return {"VT_Malicious": "-", "VT_Suspicious": "-", "VT_Tags": "-"}
    
# Enrich with GreyNoise
def enrich_greynoise(ioc: str, keys=None) -> dict:
    if detect_type(ioc) != "IP":
        log_api_call("greynoise-skipped", {}, params={"ioc": ioc}, error="Not an IP address, skipping GreyNoise")
        return {"GN_Classification": "-", "GN_Name": "-", "GN_Tags": "-"}
    keys = get_keys(keys)
    gn_key = keys.get("greynoise")
    url = f"https://api.greynoise.io/v3/community/{ioc}"
    headers = {"key": gn_key or "", "accept": "application/json"}
    if not gn_key:
        log_api_call(url, headers, params=None, error="GreyNoise key missing or empty")
        return {"GN_Classification": "-", "GN_Name": "-", "GN_Tags": "-"}
    try:
        resp = requests.get(url, headers=headers, timeout=10)
        data = resp.json()
        log_api_call(url, headers, params=None, response=data)
        if resp.status_code == 404:
            return {"GN_Classification": "unknown", "GN_Name": "-", "GN_Tags": "-"}
        tags = data.get("tags", [])
        return {
            "GN_Classification": data.get("classification", "-"),
            "GN_Name": data.get("name", "-"),
            "GN_Tags": ", ".join(tags) if tags else "-",
        }
    except Exception as e:
        log_api_call(url, headers, params=None, error=e)
        return {"GN_Classification": "error", "GN_Name": "-", "GN_Tags": "-"}

# Enrich with IPinfo
def enrich_ipinfo(ioc: str, keys=None) -> dict:
    if detect_type(ioc) != "IP":
        log_api_call("ipinfo-skipped", {}, params={"ioc": ioc}, error="Not an IP address, skipping IPinfo")
        return {"IP_Country": "-", "IP_ASN": "-"}
    keys = get_keys(keys)
    ipinfo_key = keys.get("ipinfo")
    url = f"https://ipinfo.io/{ioc}/json"
    headers = {}
    if ipinfo_key:
        headers["Authorization"] = f"Bearer {ipinfo_key}"
    if not ipinfo_key:
        log_api_call(url, headers, params=None, error="IPinfo key missing or empty")
        return {"IP_Country": "-", "IP_ASN": "-"}
    try:
        resp = requests.get(url, headers=headers, timeout=10)
        data = resp.json()
        log_api_call(url, headers, params=None, response=data)
        return {
            "IP_Country": data.get("country", "-"),
            "IP_ASN": data.get("org", "-"),
        }
    except Exception as e:
        log_api_call(url, headers, params=None, error=e)
        return {"IP_Country": "-", "IP_ASN": "-"}