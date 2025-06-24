import streamlit as st

st.set_page_config(
    page_title="Log Investigator",
    layout="wide"
)

st.title("Log Investigator")

st.write("This module is for investigating logs.") 

# File type mappings
file_type_mappings = {
    "log": "Generic Log File",
    "txt": "Text File",
    "evtx": "Windows Event Log",
    "json": "JSON File",
    "xml": "XML File",
    "csv": "CSV File",
    "pcap": "Network Packet Capture",
    "pcapng": "Network Packet Capture",
    "db": "Database File",
    "sqlite": "SQLite Database",
    "bin": "Binary File",
    "syslog": "Syslog File",
    "audit": "Audit Log",
    "out": "Output File",
    "jsonl": "JSON Lines File"
}

# --- INPUT SECTION ---
accepted_types = [
    "log", "txt", "evtx", "json", "xml", "csv", "pcap", "pcapng", "db", "sqlite", "bin", "syslog", "audit", "out", "jsonl"
]

uploaded_file = st.file_uploader(
    "Upload a log or data file",
    type=accepted_types,
    help="Supported: .log, .txt, .evtx, .json, .xml, .csv, .pcap, .pcapng, .db, .sqlite, .bin, .syslog, .audit, .out, .jsonl"
)

# Store input for further processing
if uploaded_file is not None:
    data_source = uploaded_file
    file_extension = uploaded_file.name.split('.')[-1].lower()
    file_type = file_type_mappings.get(file_extension, "Unknown file type")
    st.success(f"Successfully uploaded '{uploaded_file.name}' ({file_type}).")
else:
    st.info("Please upload a file to proceed.") 