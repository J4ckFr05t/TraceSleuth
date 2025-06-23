import streamlit as st

st.set_page_config(
    page_title="Log Investigator",
    layout="wide"
)

st.title("Log Investigator")

st.write("This module is for investigating logs.") 

# --- INPUT SECTION ---
accepted_types = [
    "log", "txt", "evtx", "json", "xml", "csv", "pcap", "pcapng", "gz", "zip", "db", "sqlite", "bin", "syslog", "audit", "out", "jsonl"
]

uploaded_file = st.file_uploader(
    "Upload a log or data file",
    type=accepted_types,
    help="Supported: .log, .txt, .evtx, .json, .xml, .csv, .pcap, .pcapng, .gz, .zip, .db, .sqlite, .bin, .syslog, .audit, .out, .jsonl"
)

# Store input for further processing
if uploaded_file is not None:
    data_source = uploaded_file
    st.success(f"File '{uploaded_file.name}' uploaded.")
else:
    st.info("Please upload a file to proceed.") 