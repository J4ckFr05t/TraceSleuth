import streamlit as st
import time

# Show loader only on first load
if "loaded" not in st.session_state:
    st.session_state.loaded = False

if not st.session_state.loaded:
    loader_html = """
    <style>
    /* Fullscreen overlay */
    #ts-loader-overlay {
        position: fixed;
        top: 0; left: 0; right: 0; bottom: 0;
        width: 100vw; height: 100vh;
        background: #111; /* or #fff for white */
        z-index: 99999;
        display: flex;
        align-items: center;
        justify-content: center;
    }
    #ts-loader-overlay .loader {
        position: relative;
        display: flex;
        align-items: center;
        justify-content: center;
        width: 6rem;
        height: 6rem;
    }
    #ts-loader-overlay .loader:before,
    #ts-loader-overlay .loader:after {
        content: "";
        position: absolute;
        border-radius: 50%;
        animation: pulsOut 1.8s ease-in-out infinite;
        filter: drop-shadow(0 0 1rem rgba(255,255,255,0.75));
    }
    #ts-loader-overlay .loader:before {
        width: 100%;
        height: 100%;
        box-shadow: inset 0 0 0 1rem #fff;
        animation-name: pulsIn;
    }
    #ts-loader-overlay .loader:after {
        width: calc(100% - 2rem);
        height: calc(100% - 2rem);
        box-shadow: 0 0 0 0 #fff;
    }
    @keyframes pulsIn {
        0% {
            box-shadow: inset 0 0 0 1rem #fff;
            opacity: 1;
        }
        50%, 100% {
            box-shadow: inset 0 0 0 0 #fff;
            opacity: 0;
        }
    }
    @keyframes pulsOut {
        0%, 50% {
            box-shadow: 0 0 0 0 #fff;
            opacity: 0;
        }
        100% {
            box-shadow: 0 0 0 1rem #fff;
            opacity: 1;
        }
    }
    /* Hide Streamlit sidebar and main content while loading */
    [data-testid="stSidebar"], [data-testid="stHeader"], [data-testid="stToolbar"], [data-testid="stAppViewContainer"] > div:first-child {
        filter: blur(2px);
        pointer-events: none;
        user-select: none;
    }
    </style>
    <div id="ts-loader-overlay">
        <div class="loader"></div>
    </div>
    """
    st.markdown(loader_html, unsafe_allow_html=True)
    time.sleep(1.5)
    st.session_state.loaded = True
    st.rerun()

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