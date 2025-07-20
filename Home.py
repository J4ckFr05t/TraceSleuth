import streamlit as st
st.set_page_config(page_title="TraceSleuth", page_icon="static/favicon_io/favicon-32x32.png", layout="wide")

st.title("Welcome to TraceSleuth!")

st.markdown("""
## What is TraceSleuth?
TraceSleuth is your all-in-one cybersecurity analysis and response platform, designed for security professionals to rapidly investigate, enrich, and visualize threat data and logs.
""")

st.markdown("""
## Key Features
- **IOC Enrichment:** Paste or upload indicators of compromise (IOCs) such as IPs, domains, or hashes. Instantly enrich them with threat intelligence from OTX, VirusTotal, GreyNoise, and IPinfo. Visualize threat levels, tags, geolocation, ASN, and more. Download results for reporting.
- **Log Investigator:** Upload and analyze logs (EVTX, JSON, CSV, PCAP, and more). Parse, visualize, and filter events. Highlight high-value events, extract and enrich IOCs, and explore process ancestry, timelines, and network flows.
- **API Key Management:** Securely manage your API keys for threat intelligence services. Keys are stored only in your session and never leave your browser.
""")

st.markdown("""
## Getting Started
1. **Configure API Keys:**
   - Go to the **Configure API Keys** page from the sidebar.
   - Enter your API keys manually or upload a YAML/JSON file with your keys.
   - Keys are required for full enrichment features (OTX, VirusTotal, GreyNoise, IPinfo).
2. **Select a Tool:**
   - Choose **IOC Enrichment** to analyze indicators of compromise.
   - Choose **Log Investigator** to upload and investigate logs or network captures.
3. **Analyze & Download:**
   - Use the interactive dashboards, visualizations, and enrichment results.
   - Download enriched data for further analysis or reporting.
""")

st.info("**API Key Handling:**\n- API keys are stored only in your session and are lost on reload for your security.\n- You can clear all keys at any time from the Configure page.\n- Your keys are never sent to any server except the official threat intelligence APIs during enrichment.")

st.success("Select a tool from the sidebar to get started!")

st.markdown("""
---
### 🚀 Other Apps from the Developer
- [Nearaa: Fuzzy Matching Tool](https://nearaa.streamlit.app/)  
  Quickly find similar records using advanced fuzzy matching algorithms.
- [DataSleuth: Data Analysis & Visualization](https://datasleuth.streamlit.app/)  
  Analyze and visualize your data with interactive dashboards and tools.
- [Developer Portfolio: Jibin George](https://jibingeorge.org/)  
  Learn more about the developer, projects, and cybersecurity expertise.
""")