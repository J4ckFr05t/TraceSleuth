import streamlit as st
import pandas as pd
from utils.api_clients import detect_type, enrich_otx, enrich_vt
from concurrent.futures import ThreadPoolExecutor

st.title("🔬 IOC Enrichment Engine")
st.markdown("Paste IOCs below or upload a CSV file.")

# --- INPUT ---
ioc_input = st.text_area("Enter IOCs", height=150)
uploaded_file = st.file_uploader("Upload CSV", type=["csv"])

ioc_list = []

if uploaded_file:
    df = pd.read_csv(uploaded_file)
    ioc_list = df.iloc[:, 0].dropna().astype(str).tolist()
elif ioc_input:
    ioc_list = list(set(i.strip() for i in ioc_input.splitlines() if i.strip()))

if st.button("🧠 Enrich IOCs") and ioc_list:
    st.info(f"Enriching {len(ioc_list)} IOCs via OTX & VirusTotal...")
    
    results = []

    def enrich(ioc):
        result = {
            "IOC": ioc,
            "Type": detect_type(ioc),
        }
        result.update(enrich_otx(ioc))
        result.update(enrich_vt(ioc))
        return result

    with ThreadPoolExecutor(max_workers=10) as executor:
        enriched = list(executor.map(enrich, ioc_list))

    df_results = pd.DataFrame(enriched)
    st.dataframe(df_results)

    csv = df_results.to_csv(index=False).encode('utf-8')
    st.download_button("📥 Download CSV", data=csv, file_name="ioc_enriched.csv", mime='text/csv')
else:
    st.warning("Paste IOCs or upload a CSV to begin.")