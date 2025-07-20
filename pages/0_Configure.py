import streamlit as st
import yaml
import json

st.set_page_config(page_title="Configure", page_icon="static/favicon_io/favicon-32x32.png", layout="wide")

st.title("🔑 Configure API Keys")

st.markdown("""
Enter your API keys for threat intelligence services below.**Keys are stored only in your session and will be lost on reload.**
You can also upload a YAML or JSON file with the following structure:

```yaml
api_keys:
  otx: "..."
  virustotal: "..."
  greynoise: "..."
  ipinfo: "..."
```

or

```json
{
  "api_keys": {
    "otx": "...",
    "virustotal": "...",
    "greynoise": "...",
    "ipinfo": "..."
  }
}
```
""")

# Helper: set keys in session state
def set_keys(keys_dict):
    if "api_keys" not in st.session_state:
        st.session_state["api_keys"] = {}
    st.session_state["api_keys"].update(keys_dict)

# Upload section
uploaded = st.file_uploader("Upload YAML or JSON with API keys", type=["yaml", "yml", "json"])
if uploaded:
    try:
        if uploaded.name.endswith((".yaml", ".yml")):
            data = yaml.safe_load(uploaded.read())
        else:
            data = json.load(uploaded)
        if "api_keys" in data:
            set_keys(data["api_keys"])
            st.success("API keys loaded from file!")
        else:
            st.error("File must contain an 'api_keys' section.")
    except Exception as e:
        st.error(f"Failed to parse file: {e}")

st.markdown("---")

# Manual entry section
st.subheader("Manual Entry")
def manual_key_input(label, key_name):
    value = st.text_input(label, type="password", value=st.session_state.get("api_keys", {}).get(key_name, ""))
    if value:
        set_keys({key_name: value})

manual_key_input("OTX API Key", "otx")
manual_key_input("VirusTotal API Key", "virustotal")
manual_key_input("GreyNoise API Key", "greynoise")
manual_key_input("IPinfo API Key", "ipinfo")

# Show current keys (masked)
if "api_keys" in st.session_state and st.session_state["api_keys"]:
    st.markdown("---")
    st.subheader("Current Session Keys")
    for k, v in st.session_state["api_keys"].items():
        st.write(f"**{k}**: {'*' * len(v) if v else ''}")
    if st.button("Clear All Keys"):
        del st.session_state["api_keys"]
        st.success("All API keys cleared from session.") 