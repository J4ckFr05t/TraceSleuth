import streamlit as st
import pandas as pd
import xml.etree.ElementTree as ET
from io import BytesIO
import tempfile
from config.high_value_events import DEFAULT_HIGH_VALUE_EVENTS
import altair as alt
from utils.api_clients import detect_type, enrich_otx, enrich_vt, enrich_greynoise
from functools import lru_cache
import ipaddress
import networkx as nx
from pyvis.network import Network
import streamlit.components.v1 as components
import numpy as np
import sqlite3
import duckdb
import os
import json
import xml.dom.minidom
import binascii
from collections import defaultdict, deque
from concurrent.futures import ThreadPoolExecutor

st.set_page_config(page_title="Log Investigator", page_icon="static/favicon_io/favicon-32x32.png", layout="wide")

st.title("🔍 Log Investigator")

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

    if file_extension == "evtx":
        try:
            from Evtx.Evtx import Evtx
        except ImportError:
            Evtx = None
        if Evtx is None:
            st.error("python-evtx is not installed. Please install it using 'pip install python-evtx'.")
        else:
            user_event_ids = st.text_input(
                "🛡️ Enter high-value Event IDs (comma-separated)",
                value=",".join(DEFAULT_HIGH_VALUE_EVENTS),
                help="Customize which Event IDs you want to highlight in your investigation."
            )
            high_value_ids = [e.strip() for e in user_event_ids.split(",") if e.strip()]
            show_only_high_value = st.checkbox("Show only high-value events", value=False)
            records = []
            with tempfile.NamedTemporaryFile(delete=True, suffix='.evtx') as tmpfile:
                tmpfile.write(uploaded_file.read())
                tmpfile.flush()
                with Evtx(tmpfile.name) as evtx:
                    for record in evtx.records():
                        xml_str = record.xml()
                        try:
                            root = ET.fromstring(xml_str)
                            ns = {'e': 'http://schemas.microsoft.com/win/2004/08/events/event'}
                            event_id = root.findtext('.//e:EventID', namespaces=ns)
                            is_high_value = event_id in high_value_ids
                            time_created = root.find('.//e:TimeCreated', namespaces=ns)
                            timestamp = time_created.attrib.get('SystemTime') if time_created is not None else None
                            image = command_line = parent_image = src_ip = dst_ip = None
                            for data in root.findall('.//e:Data', namespaces=ns):
                                name = data.attrib.get('Name', '').lower()
                                val = data.text
                                if name == 'image':
                                    image = val
                                elif name == 'commandline':
                                    command_line = val
                                elif name == 'parentimage':
                                    parent_image = val
                                elif name == 'sourceip':
                                    src_ip = val
                                elif name == 'destinationip':
                                    dst_ip = val
                            for data in root.findall('.//e:Data', namespaces=ns):
                                name = data.attrib.get('Name', '').lower()
                                val = data.text
                                if not src_ip and name in ('ipaddress', 'source address'):
                                    src_ip = val
                                if not dst_ip and name in ('destination address', 'destaddress'):
                                    dst_ip = val
                            records.append({
                                'EventID': event_id,
                                'TimeCreated': timestamp,
                                'Image': image,
                                'CommandLine': command_line,
                                'ParentImage': parent_image,
                                'SourceIp': src_ip,
                                'DestinationIp': dst_ip,
                                'HighValue': is_high_value  # Use boolean only
                            })
                        except Exception as e:
                            continue  # skip malformed records
            if records:
                df = pd.DataFrame(records)
                if show_only_high_value:
                    df = df[df['HighValue']]
                # st.dataframe(df, use_container_width=True)  # Removed duplicate table view

                # Ensure IOC_Hit column exists (default False for now)
                if 'IOC_Hit' not in df.columns:
                    df['IOC_Hit'] = False
                # Ensure HighValue column is boolean for plotting
                df['HighValue'] = df['HighValue'].astype(bool)
                # EventType for plotting
                if 'EventType' not in df.columns:
                    EVENT_TYPE_MAP = {
                        "1": "Process Create",
                        "3": "Network Connect",
                        "7": "Image Load",
                        "11": "File Create",
                        "22": "DNS Query",
                        "4624": "Logon Success",
                        "4625": "Logon Failure",
                        "4688": "Process Create",
                        "7045": "Service Install",
                        "4720": "New User Account",
                        "1102": "Audit Log Cleared"
                    }
                    df['EventType'] = df['EventID'].map(EVENT_TYPE_MAP).fillna('Other')
                # Parse Timestamp to datetime
                df['Timestamp'] = pd.to_datetime(df['TimeCreated'], errors='coerce')

                # --- Interactive Timeline Filters ---
                st.markdown('### 📈 Interactive Timeline')
                col1, col2, col3 = st.columns(3)
                with col1:
                    filter_high_value = st.checkbox('Show only high-value events (🟡)', value=False)
                with col2:
                    filter_ioc = st.checkbox('Show only IOC hits (🔴)', value=False)
                with col3:
                    event_types = df['EventType'].unique().tolist()
                    filter_event_types = st.multiselect('Event Types', event_types, default=event_types)

                filtered_df = df.copy()
                if filter_high_value:
                    filtered_df = filtered_df[filtered_df['HighValue']]
                if filter_ioc:
                    filtered_df = filtered_df[filtered_df['IOC_Hit']]
                if filter_event_types:
                    filtered_df = filtered_df[filtered_df['EventType'].isin(filter_event_types)]

                # Precompute color for each event in the DataFrame to avoid nested alt.condition
                def get_event_color(row):
                    if row['IOC_Hit']:
                        return 'red'
                    elif row['HighValue']:
                        return 'orange'
                    else:
                        return 'gray'
                filtered_df['EventColor'] = filtered_df.apply(get_event_color, axis=1)

                # Ensure 'Description' field exists and is string
                if 'Description' not in filtered_df.columns:
                    filtered_df['Description'] = ''
                filtered_df['Description'] = filtered_df['Description'].astype(str)

                chart = alt.Chart(filtered_df).mark_circle(size=60).encode(
                    x=alt.X('Timestamp:T', title='Timestamp'),
                    y=alt.Y('EventType:N', title='Event Type'),
                    color=alt.Color('EventColor:N', scale=None, legend=None),
                    tooltip=['Timestamp', 'EventID', 'EventType', 'Description', 'HighValue', 'IOC_Hit']
                ).interactive().properties(height=400)

                st.altair_chart(chart, use_container_width=True)

                st.markdown("---")
                st.markdown("### Table View")
                st.dataframe(df, use_container_width=True, column_config={
                    'HighValue': st.column_config.CheckboxColumn(help="Is this a high-value event?")
                })

                # --- Process Ancestry Indented View ---
                st.markdown('### 🧬 Process Ancestry (Threaded View)')
                proc_df = df[df['EventType'] == 'Process Create'][['Image', 'ParentImage', 'Timestamp']].copy()
                proc_df = proc_df.sort_values('Timestamp')
                # Build mapping: parent -> [children]
                children_map = defaultdict(list)
                parent_set = set()
                image_set = set()
                for _, row in proc_df.iterrows():
                    parent = row['ParentImage']
                    child = row['Image']
                    children_map[parent].append(child)
                    parent_set.add(parent)
                    image_set.add(child)
                # Roots: Images whose ParentImage is not in Image set
                roots = [img for img in image_set if img not in parent_set]
                # To avoid missing chains, also include any process whose parent is None or empty
                roots += [row['Image'] for _, row in proc_df.iterrows() if not row['ParentImage'] or pd.isna(row['ParentImage'])]
                roots = list(set(roots))
                # DFS to print ancestry
                def print_tree(node, depth, visited):
                    if node in visited:
                        return ''  # avoid cycles
                    visited.add(node)
                    indent = '    ' * depth + '└── '
                    s = f"{indent}{node}\n"
                    for child in children_map.get(node, []):
                        s += print_tree(child, depth+1, visited)
                    return s
                ancestry_str = ''
                visited = set()
                for root in roots:
                    ancestry_str += print_tree(root, 0, visited)
                if ancestry_str.strip():
                    st.markdown(f"```\n{ancestry_str}```")
                else:
                    st.info('No process ancestry chains found.')

                # --- IOC HIT ENRICHMENT ---
                st.markdown('#### 🔎 IOC Hit Detection')
                
                # Collect all unique IOCs from the dataframe
                ioc_candidates = set()
                for value in df.astype(str).values.flatten():
                    if isinstance(value, str) and value.strip():
                        ioc_type = detect_type(value)
                        if ioc_type in ("IP", "Hash", "Domain"):
                            ioc_candidates.add(value.strip())
                
                if ioc_candidates:
                    st.write(f"Found {len(ioc_candidates)} unique IOCs to check for hits...")
                    
                    # Before any ThreadPoolExecutor usage, extract keys ONCE in main thread
                    # For each enrichment block, do this:

                    # Example for one enrichment block:
                    keys = st.session_state.get('api_keys', {})  # Extract keys ONCE in main thread
                    @lru_cache(maxsize=512)
                    def enrich_all(ioc):
                        result = {"IOC": ioc, "Type": detect_type(ioc)}
                        result.update(enrich_otx(ioc, keys=keys))
                        result.update(enrich_vt(ioc, keys=keys))
                        result.update(enrich_greynoise(ioc, keys=keys))
                        try:
                            from utils.api_clients import enrich_ipinfo
                            result.update(enrich_ipinfo(ioc, keys=keys))
                        except ImportError:
                            pass
                        return result

                    def is_ioc_hit(enrichment_result):
                        otx_malicious = enrichment_result.get('OTX_Malicious', False)
                        vt_malicious = enrichment_result.get('VT_Malicious', 0)
                        gn_class = str(enrichment_result.get('GN_Classification', '')).lower()
                        
                        if otx_malicious is True:
                            return True
                        if isinstance(vt_malicious, int) and vt_malicious > 0:
                            return True
                        if gn_class == 'malicious':
                            return True
                        return False

                    # Parallel enrichment with progress bar
                    progress_bar = st.progress(0)
                    status_text = st.empty()
                    
                    enriched_results = {}
                    ioc_list = list(ioc_candidates)
                    
                    with ThreadPoolExecutor(max_workers=10) as executor:
                        # Submit all tasks
                        future_to_ioc = {executor.submit(enrich_all, ioc): ioc for ioc in ioc_list}
                        
                        # Process completed tasks with progress updates
                        for i, future in enumerate(future_to_ioc):
                            try:
                                result = future.result()
                                enriched_results[result['IOC']] = result
                                progress = (i + 1) / len(ioc_list)
                                progress_bar.progress(progress)
                                status_text.text(f"Enriching IOCs... {i + 1}/{len(ioc_list)} ({progress:.1%})")
                            except Exception as e:
                                st.warning(f"Error enriching IOC: {e}")
                                continue
                    
                    # Clear progress indicators
                    progress_bar.empty()
                    status_text.empty()
                    
                    # Create a mapping of IOCs to their hit status
                    ioc_hit_map = {ioc: is_ioc_hit(result) for ioc, result in enriched_results.items()}
                    
                    # Update the dataframe with IOC hits
                    for idx, row in df.iterrows():
                        ioc_found = False
                        for value in row.values:
                            if isinstance(value, str) and value.strip() in ioc_hit_map:
                                if ioc_hit_map[value.strip()]:
                                    ioc_found = True
                                    break
                        df.at[idx, 'IOC_Hit'] = ioc_found
                    
                    # Show enrichment results summary
                    hit_count = sum(ioc_hit_map.values())
                    st.success(f"✅ IOC enrichment completed! Found {hit_count} malicious IOCs out of {len(ioc_candidates)} total IOCs.")
                    
                    # Display detailed enrichment results
                    if enriched_results:
                        st.markdown('##### 📊 IOC Enrichment Results')
                        df_enrich = pd.DataFrame(list(enriched_results.values()))
                        
                        # Add navigation links
                        df_enrich['VT'] = df_enrich.apply(lambda row: f"https://www.virustotal.com/gui/search/{row['IOC']}", axis=1)
                        df_enrich['OTX'] = df_enrich.apply(lambda row: f"https://otx.alienvault.com/indicator/{row['Type'].lower()}/{row['IOC']}", axis=1)
                        df_enrich['GN'] = df_enrich.apply(
                            lambda row: f"https://www.greynoise.io/viz/ip/{row['IOC']}" if 'ip' in row['Type'].lower() else None,
                            axis=1
                        )
                        
                        # Define column configuration for links
                        column_config = {
                            "IOC": st.column_config.TextColumn(help="The original IOC (IP, domain, or hash)"),
                            "Type": st.column_config.TextColumn(help="Automatically detected type of the indicator"),
                            "VT": st.column_config.LinkColumn(
                                "VirusTotal",
                                display_text="VT",
                                help="Pivots to the VirusTotal report"
                            ),
                            "OTX": st.column_config.LinkColumn(
                                "OTX",
                                display_text="OTX",
                                help="Pivots to the OTX report"
                            ),
                            "GN": st.column_config.LinkColumn(
                                "GreyNoise",
                                display_text="GN",
                                help="Pivots to the GreyNoise report"
                            ),
                        }
                        
                        # Reorder columns to show links first
                        final_column_order = ['IOC', 'Type', 'VT', 'OTX', 'GN'] + [col for col in df_enrich.columns if col not in ['IOC', 'Type', 'VT', 'OTX', 'GN']]
                        
                        st.dataframe(df_enrich[final_column_order], use_container_width=True, column_config=column_config)
                else:
                    st.info("No IOCs found in the event data for enrichment.")
            else:
                st.info("No events found in the uploaded EVTX file.")
    elif file_extension in ["pcap", "pcapng"]:
        import pyshark
        st.markdown("---")
        st.markdown("### 🕸️ Network Flow Extraction (PCAP/PCAPNG)")
        with tempfile.NamedTemporaryFile(delete=True, suffix=f'.{file_extension}') as tmpfile:
            tmpfile.write(uploaded_file.read())
            tmpfile.flush()
            st.info("Parsing network flows, this may take a moment for large files...")
            try:
                cap = pyshark.FileCapture(tmpfile.name, only_summaries=False)
                flows = []
                for pkt in cap:
                    try:
                        ts = pd.to_datetime(pkt.sniff_time)
                        proto = getattr(pkt, 'highest_layer', None) or getattr(pkt, 'transport_layer', None) or 'Unknown'
                        src_ip = getattr(pkt, 'ip', None)
                        src_ip = src_ip.src if src_ip and hasattr(src_ip, 'src') else getattr(pkt, 'ip.src', None)
                        dst_ip = getattr(pkt, 'ip', None)
                        dst_ip = dst_ip.dst if dst_ip and hasattr(dst_ip, 'dst') else getattr(pkt, 'ip.dst', None)
                        src_port = getattr(pkt, 'tcp', None)
                        src_port = src_port.srcport if src_port and hasattr(src_port, 'srcport') else getattr(pkt, 'udp', None)
                        if src_port and hasattr(src_port, 'srcport'):
                            src_port = src_port.srcport
                        else:
                            src_port = getattr(pkt, 'tcp.srcport', None) or getattr(pkt, 'udp.srcport', None)
                        dst_port = getattr(pkt, 'tcp', None)
                        dst_port = dst_port.dstport if dst_port and hasattr(dst_port, 'dstport') else getattr(pkt, 'udp', None)
                        if dst_port and hasattr(dst_port, 'dstport'):
                            dst_port = dst_port.dstport
                        else:
                            dst_port = getattr(pkt, 'tcp.dstport', None) or getattr(pkt, 'udp.dstport', None)
                        length = int(getattr(pkt, 'length', 0)) if hasattr(pkt, 'length') else None
                        # HTTP/DNS fields
                        host = uri = user_agent = None
                        if 'HTTP' in proto and hasattr(pkt.http, 'host'):
                            host = getattr(pkt.http, 'host', None)
                            uri = getattr(pkt.http, 'request_full_uri', None)
                            user_agent = getattr(pkt.http, 'user_agent', None)
                        if 'DNS' in proto and hasattr(pkt.dns, 'qry_name'):
                            host = getattr(pkt.dns, 'qry_name', None)
                        flows.append({
                            'Timestamp': ts,
                            'Protocol': proto,
                            'Source IP': src_ip,
                            'Source Port': src_port,
                            'Destination IP': dst_ip,
                            'Destination Port': dst_port,
                            'Length': length,
                            'Host/Domain': host,
                            'URI': uri,
                            'User-Agent': user_agent
                        })
                    except Exception as e:
                        continue
                cap.close()
                if not flows:
                    st.warning("No flows/packets extracted from the PCAP file.")
                else:
                    df = pd.DataFrame(flows)
                    # --- Filters ---
                    st.markdown('#### Filters')
                    col1, col2, col3 = st.columns(3)
                    with col1:
                        proto_options = df['Protocol'].dropna().unique().tolist()
                        filter_proto = st.multiselect('Protocol', proto_options, default=proto_options)
                    with col2:
                        dst_ip_options = df['Destination IP'].dropna().unique().tolist()
                        filter_dst_ip = st.multiselect('Destination IP', dst_ip_options, default=dst_ip_options)
                    with col3:
                        filter_dns_http = st.checkbox('Show only DNS/HTTP traffic', value=False)
                    filtered_df = df.copy()
                    if filter_proto:
                        filtered_df = filtered_df[filtered_df['Protocol'].isin(filter_proto)]
                    if filter_dst_ip:
                        filtered_df = filtered_df[filtered_df['Destination IP'].isin(filter_dst_ip)]
                    if filter_dns_http:
                        filtered_df = filtered_df[filtered_df['Protocol'].isin(['HTTP', 'DNS'])]
                    st.markdown('#### Network Flows Table')
                    st.dataframe(filtered_df, use_container_width=True)
                    # --- Timeline Chart ---
                    st.markdown('#### 📈 Timeline of Connections')
                    if not filtered_df.empty:
                        timeline_df = filtered_df.copy()
                        timeline_df['Minute'] = timeline_df['Timestamp'].dt.floor('min')
                        timeline_counts = timeline_df.groupby('Minute').size().reset_index(name='Count')
                        chart = alt.Chart(timeline_counts).mark_line(point=True).encode(
                            x=alt.X('Minute:T', title='Time'),
                            y=alt.Y('Count:Q', title='Number of Flows'),
                            tooltip=['Minute', 'Count']
                        ).properties(height=300)
                        st.altair_chart(chart, use_container_width=True)
                    # --- Protocol Distribution Charts ---
                    st.markdown('#### 🥧 Protocol Distribution')
                    
                    # Calculate protocol statistics
                    proto_counts = filtered_df['Protocol'].value_counts().reset_index()
                    proto_counts.columns = ['Protocol', 'Count']
                    total_packets = proto_counts['Count'].sum()
                    proto_counts['Percentage'] = (proto_counts['Count'] / total_packets * 100).round(1)
                    proto_counts['Label'] = proto_counts['Protocol'] + ' (' + proto_counts['Percentage'].astype(str) + '%)'
                    
                    # Bar chart showing percentages
                    bar = alt.Chart(proto_counts).mark_bar().encode(
                        x=alt.X('Percentage:Q', title='Percentage (%)'),
                        y=alt.Y('Protocol:N', title='Protocol', sort='-x'),
                        color=alt.Color('Protocol:N', legend=None),
                        tooltip=[
                            alt.Tooltip('Protocol:N', title='Protocol'),
                            alt.Tooltip('Count:Q', title='Count'),
                            alt.Tooltip('Percentage:Q', title='Percentage', format='.1f')
                        ]
                    ).properties(height=400, title='Protocol Distribution by Percentage')
                    
                    # Add percentage labels on bars
                    bar_text = alt.Chart(proto_counts).mark_text(
                        align='left',
                        baseline='middle',
                        dx=5,
                        fontSize=11,
                        fontWeight='bold'
                    ).encode(
                        x=alt.X('Percentage:Q'),
                        y=alt.Y('Protocol:N', sort='-x'),
                        text=alt.Text('Percentage:Q', format='.1f')
                    )
                    
                    bar_chart = alt.layer(bar, bar_text)
                    st.altair_chart(bar_chart, use_container_width=True)
                    
                    # Summary statistics
                    st.markdown('##### 📊 Protocol Summary')
                    summary_col1, summary_col2, summary_col3 = st.columns(3)
                    with summary_col1:
                        st.metric("Total Packets", f"{total_packets:,}")
                    with summary_col2:
                        st.metric("Unique Protocols", len(proto_counts))
                    with summary_col3:
                        top_protocol = proto_counts.iloc[0]
                        st.metric("Most Common", f"{top_protocol['Protocol']} ({top_protocol['Percentage']:.1f}%)")
                    # --- Source-Destination Graph (Improved: Internal/External Separation) ---
                    st.markdown('#### 🌐 Source-Destination Graphs (Internal ↔ External)')
                    def is_internal(ip):
                        try:
                            return ipaddress.ip_address(ip).is_private
                        except Exception:
                            return False

                    # Prepare flows for graphing
                    flow_counts = {}
                    for _, row in filtered_df.iterrows():
                        src = row['Source IP']
                        dst = row['Destination IP']
                        if src and dst and src != dst:
                            key = (src, dst)
                            flow_counts[key] = flow_counts.get(key, 0) + 1

                    # Group flows
                    internal_to_external = {}
                    external_to_internal = {}
                    for (src, dst), count in flow_counts.items():
                        src_internal = is_internal(src)
                        dst_internal = is_internal(dst)
                        if src_internal and not dst_internal:
                            internal_to_external[(src, dst)] = count
                        elif not src_internal and dst_internal:
                            external_to_internal[(src, dst)] = count

                    # Helper to build and render a pyvis graph
                    def build_pyvis_graph(flow_dict, direction_label):
                        net = Network(height='500px', width='100%', bgcolor='#181818', font_color='white', directed=True)
                        node_types = {}
                        for (src, dst), count in flow_dict.items():
                            for ip, is_int in [(src, is_internal(src)), (dst, is_internal(dst))]:
                                if ip not in node_types:
                                    node_types[ip] = is_int
                        for ip, is_int in node_types.items():
                            color = '#4FC3F7' if is_int else '#FF7043'  # blue for internal, orange for external
                            net.add_node(ip, label=ip, color=color, font={'color': 'white'})
                        max_count = max(flow_dict.values()) if flow_dict else 1
                        for (src, dst), count in flow_dict.items():
                            width = 1 + 6 * (count / max_count)  # 1-7 px
                            net.add_edge(src, dst, value=count, title=f"{src} → {dst}<br>Packets: {count}", width=width, color='#BDBDBD')
                        net.set_options('''
                        var options = {
                          "nodes": {
                            "borderWidth": 2,
                            "shadow": true,
                            "font": { "color": "white", "size": 16 }
                          },
                          "edges": {
                            "color": { "color": "#BDBDBD" },
                            "smooth": true,
                            "arrows": { "to": { "enabled": true, "scaleFactor": 0.7 } },
                            "shadow": true
                          },
                          "layout": {
                            "improvedLayout": true
                          },
                          "physics": {
                            "enabled": true,
                            "barnesHut": { "gravitationalConstant": -8000, "springLength": 120, "springConstant": 0.04 }
                          },
                          "interaction": {
                            "hover": true,
                            "tooltipDelay": 100
                          },
                          "manipulation": { "enabled": false },
                          "autoResize": true
                        }
                        ''')
                        html = net.generate_html()
                        # Inject CSS to remove white border/background
                        dark_css = '''<style>
                        body { background: #181818 !important; }
                        #mynetwork { background: #181818 !important; border: none !important; }
                        .vis-network { background: #181818 !important; }
                        div { border: none !important; }
                        </style>'''
                        if '</head>' in html:
                            html = html.replace('</head>', f'{dark_css}</head>')
                        else:
                            html = dark_css + html
                        return html

                    col1, col2 = st.columns(2)
                    with col1:
                        st.markdown('**Internal → External**')
                        if internal_to_external:
                            net1 = build_pyvis_graph(internal_to_external, 'Internal → External')
                            components.html(net1, height=520, scrolling=False)
                        else:
                            st.info('No Internal → External flows found.')
                    with col2:
                        st.markdown('**External → Internal**')
                        if external_to_internal:
                            net2 = build_pyvis_graph(external_to_internal, 'External → Internal')
                            components.html(net2, height=520, scrolling=False)
                        else:
                            st.info('No External → Internal flows found.')
                    
                # --- Port Usage Analysis ---
                st.markdown('#### 🔢 Port Usage Analysis')

                # Extract relevant info for TCP/UDP packets
                tcp_udp_rows = []
                for pkt in cap:
                    try:
                        proto = getattr(pkt, 'transport_layer', None)
                        if proto not in ('TCP', 'UDP'):
                            continue
                        src_ip = getattr(pkt, 'ip', None)
                        src_ip = src_ip.src if src_ip and hasattr(src_ip, 'src') else getattr(pkt, 'ip.src', None)
                        dst_ip = getattr(pkt, 'ip', None)
                        dst_ip = dst_ip.dst if dst_ip and hasattr(dst_ip, 'dst') else getattr(pkt, 'ip.dst', None)
                        src_port = getattr(pkt, proto.lower(), None)
                        src_port = src_port.srcport if src_port and hasattr(src_port, 'srcport') else getattr(pkt, f'{proto.lower()}.srcport', None)
                        dst_port = getattr(pkt, proto.lower(), None)
                        dst_port = dst_port.dstport if dst_port and hasattr(dst_port, 'dstport') else getattr(pkt, f'{proto.lower()}.dstport', None)
                        if src_ip and dst_ip and src_port and dst_port:
                            tcp_udp_rows.append({
                                'Protocol': proto,
                                'Source IP': src_ip,
                                'Destination IP': dst_ip,
                                'Source Port': str(src_port),
                                'Destination Port': str(dst_port)
                            })
                    except Exception:
                        continue

                if tcp_udp_rows:
                    port_df = pd.DataFrame(tcp_udp_rows)
                    # Protocol filter
                    proto_options = port_df['Protocol'].unique().tolist()
                    proto_filter = st.multiselect('Protocol', proto_options, default=proto_options, key='port_proto_filter')
                    filtered_port_df = port_df[port_df['Protocol'].isin(proto_filter)]
                    # Toggle between source/destination port
                    port_type = st.radio('Show Top Ports by:', ['Destination Port', 'Source Port'], horizontal=True)
                    port_col = 'Destination Port' if port_type == 'Destination Port' else 'Source Port'
                    # Aggregate counts
                    agg = filtered_port_df.groupby(['Protocol', port_col]).size().reset_index(name='Packet Count')
                    # Top N
                    N = st.slider('Show Top N Ports', min_value=5, max_value=30, value=10, step=1)
                    top_ports = agg.sort_values('Packet Count', ascending=False).head(N)
                    # Bar chart
                    bar_chart = alt.Chart(top_ports).mark_bar().encode(
                        x=alt.X('Packet Count:Q', title='Packet Count'),
                        y=alt.Y(f'{port_col}:N', title=port_col, sort='-x'),
                        color=alt.Color('Protocol:N', legend=alt.Legend(title='Protocol')),
                        tooltip=['Protocol', port_col, 'Packet Count']
                    ).properties(height=400, title=f'Top {N} {port_type}s by Packet Count')
                    st.altair_chart(bar_chart.configure(
                        background='#181818',
                        axis=alt.AxisConfig(labelColor='white', titleColor='white'),
                        legend=alt.LegendConfig(labelColor='white', titleColor='white'),
                        title=alt.TitleConfig(color='white')
                    ), use_container_width=True)
                    # Table
                    st.markdown('##### Port Flow Table')
                    flow_agg = filtered_port_df.groupby(['Source IP', 'Destination IP', 'Source Port', 'Destination Port', 'Protocol']).size().reset_index(name='Packet Count')
                    st.dataframe(flow_agg, use_container_width=True, height=400)
                else:
                    st.info('No TCP/UDP packets found for port analysis.')

                # --- Packet Size Analysis ---
                st.markdown('#### 📦 Packet Size Analysis')

                packet_sizes = []
                timestamps = []
                for pkt in cap:
                    try:
                        length = int(getattr(pkt, 'length', None) or getattr(pkt, 'frame_info', None) and getattr(pkt.frame_info, 'len', None) or getattr(pkt, 'frame.len', None) or 0)
                        ts = getattr(pkt, 'sniff_time', None)
                        if length > 0:
                            packet_sizes.append(length)
                            timestamps.append(ts)
                    except Exception:
                        continue

                if packet_sizes:
                    size_df = pd.DataFrame({'Packet Size (bytes)': packet_sizes, 'Timestamp': timestamps})
                    # Histogram
                    st.markdown('**Histogram of Packet Sizes**')
                    hist = alt.Chart(size_df).mark_bar().encode(
                        alt.X('Packet Size (bytes):Q', bin=alt.Bin(maxbins=40), title='Packet Size (bytes)'),
                        alt.Y('count()', title='Number of Packets'),
                        tooltip=[alt.Tooltip('count()', title='Packets'), alt.Tooltip('Packet Size (bytes):Q', title='Size')]
                    ).properties(height=350, title='Packet Size Distribution')
                    st.altair_chart(hist.configure(
                        background='#181818',
                        axis=alt.AxisConfig(labelColor='white', titleColor='white'),
                        legend=alt.LegendConfig(labelColor='white', titleColor='white'),
                        title=alt.TitleConfig(color='white')
                    ), use_container_width=True)
                    # Boxplot (optional)
                    st.markdown('**Boxplot of Packet Sizes**')
                    box = alt.Chart(size_df).mark_boxplot(extent='min-max').encode(
                        y=alt.Y('Packet Size (bytes):Q', title='Packet Size (bytes)'),
                        color=alt.value('#4FC3F7')
                    ).properties(height=200, title='Packet Size Boxplot')
                    st.altair_chart(box.configure(
                        background='#181818',
                        axis=alt.AxisConfig(labelColor='white', titleColor='white'),
                        title=alt.TitleConfig(color='white')
                    ), use_container_width=True)
                    # Time series (optional)
                    st.markdown('**Packet Size Over Time**')
                    if size_df['Timestamp'].notnull().any():
                        size_df['Timestamp'] = pd.to_datetime(size_df['Timestamp'])
                        ts_chart = alt.Chart(size_df).mark_line(point=True).encode(
                            x=alt.X('Timestamp:T', title='Time'),
                            y=alt.Y('Packet Size (bytes):Q', title='Packet Size (bytes)'),
                            tooltip=['Timestamp', 'Packet Size (bytes)']
                        ).properties(height=250, title='Packet Size Over Time')
                        st.altair_chart(ts_chart.configure(
                            background='#181818',
                            axis=alt.AxisConfig(labelColor='white', titleColor='white'),
                            title=alt.TitleConfig(color='white')
                        ), use_container_width=True)
                    # Descriptive stats
                    st.markdown('**Descriptive Statistics**')
                    stats = {
                        'Min Size': int(np.min(packet_sizes)),
                        'Max Size': int(np.max(packet_sizes)),
                        'Median': float(np.median(packet_sizes)),
                        'Mean': float(np.mean(packet_sizes)),
                        'Std Deviation': float(np.std(packet_sizes)),
                        'Total Packets': len(packet_sizes)
                    }
                    st.dataframe(pd.DataFrame(stats, index=[0]), use_container_width=True)
                else:
                    st.info('No packet size data found in this PCAP.')

                # --- Prepare for IOC Enrichment ---
                st.markdown('#### 🔎 IOC Enrichment for Network Flows')
                # Collect unique IOCs (IPs/domains/FQDNs/DNS names)
                ioc_candidates = set()
                for col in ['Source IP', 'Destination IP', 'Host/Domain']:
                    ioc_candidates.update(filtered_df[col].dropna().astype(str).tolist())
                # Remove empty/invalid
                ioc_candidates = set(ioc for ioc in ioc_candidates if ioc and ioc != 'None' and ioc != '-')
                # Detect type and filter for IP, Domain, FQDN, DNS
                ioc_list = []
                for ioc in ioc_candidates:
                    t = detect_type(ioc)
                    if t in ("IP", "Domain"):
                        ioc_list.append(ioc)
                if ioc_list:
                    enrich_button = st.button('Run IOC Enrichment', key='pcap_enrich')
                    if enrich_button:
                        st.write(f"Enriching {len(ioc_list)} unique IOCs (IPs/domains)...")
                        
                        # Before any ThreadPoolExecutor usage, extract keys ONCE in main thread
                        # For each enrichment block, do this:

                        # Example for one enrichment block:
                        keys = st.session_state.get('api_keys', {})  # Extract keys ONCE in main thread
                        @lru_cache(maxsize=512)
                        def enrich_all(ioc):
                            result = {"IOC": ioc, "Type": detect_type(ioc)}
                            result.update(enrich_otx(ioc, keys=keys))
                            result.update(enrich_vt(ioc, keys=keys))
                            result.update(enrich_greynoise(ioc, keys=keys))
                            try:
                                from utils.api_clients import enrich_ipinfo
                                result.update(enrich_ipinfo(ioc, keys=keys))
                            except ImportError:
                                pass
                            return result
                        
                        # Parallel enrichment with progress bar
                        progress_bar = st.progress(0)
                        status_text = st.empty()
                        
                        enriched = []
                        
                        with ThreadPoolExecutor(max_workers=10) as executor:
                            # Submit all tasks
                            future_to_ioc = {executor.submit(enrich_all, ioc): ioc for ioc in ioc_list}
                            
                            # Process completed tasks with progress updates
                            for i, future in enumerate(future_to_ioc):
                                try:
                                    result = future.result()
                                    enriched.append(result)
                                    progress = (i + 1) / len(ioc_list)
                                    progress_bar.progress(progress)
                                    status_text.text(f"Enriching IOCs... {i + 1}/{len(ioc_list)} ({progress:.1%})")
                                except Exception as e:
                                    st.warning(f"Error enriching IOC: {e}")
                                    continue
                        
                        # Clear progress indicators
                        progress_bar.empty()
                        status_text.empty()
                        
                        df_enrich = pd.DataFrame(enriched)
                        
                        # Add navigation links
                        df_enrich['VT'] = df_enrich.apply(lambda row: f"https://www.virustotal.com/gui/search/{row['IOC']}", axis=1)
                        df_enrich['OTX'] = df_enrich.apply(lambda row: f"https://otx.alienvault.com/indicator/{row['Type'].lower()}/{row['IOC']}", axis=1)
                        df_enrich['GN'] = df_enrich.apply(
                            lambda row: f"https://www.greynoise.io/viz/ip/{row['IOC']}" if 'ip' in row['Type'].lower() else None,
                            axis=1
                        )
                        
                        # Define column configuration for links
                        column_config = {
                            "IOC": st.column_config.TextColumn(help="The original IOC (IP, domain, or hash)"),
                            "Type": st.column_config.TextColumn(help="Automatically detected type of the indicator"),
                            "VT": st.column_config.LinkColumn(
                                "VirusTotal",
                                display_text="VT",
                                help="Pivots to the VirusTotal report"
                            ),
                            "OTX": st.column_config.LinkColumn(
                                "OTX",
                                display_text="OTX",
                                help="Pivots to the OTX report"
                            ),
                            "GN": st.column_config.LinkColumn(
                                "GreyNoise",
                                display_text="GN",
                                help="Pivots to the GreyNoise report"
                            ),
                        }
                        
                        # Reorder columns to show links first
                        final_column_order = ['IOC', 'Type', 'VT', 'OTX', 'GN'] + [col for col in df_enrich.columns if col not in ['IOC', 'Type', 'VT', 'OTX', 'GN']]
                        
                        # Display enrichment results
                        st.markdown('##### IOC Enrichment Results')
                        st.dataframe(df_enrich[final_column_order], use_container_width=True, column_config=column_config)
                else:
                    st.info('No valid IPs or domains found for enrichment.')
            except Exception as e:
                st.error(f"Error parsing PCAP: {e}")
    elif file_extension in ["json", "jsonl"]:
        st.markdown('#### 🗂️ JSON/JSONL Viewer')
        try:
            content = uploaded_file.read().decode('utf-8')
            if file_extension == "jsonl":
                # Parse line by line
                lines = [json.loads(line) for line in content.splitlines() if line.strip()]
                df = pd.DataFrame(lines)
                # --- Stats ---
                col1, col2 = st.columns(2)
                col1.metric('Records', len(df))
                col2.metric('Unique Keys', len(set().union(*df.columns)))
                with st.expander('Example Keys'):
                    st.write(list(df.columns)[:10])
                st.write(f"Parsed {len(lines)} JSONL records.")
                st.dataframe(df, use_container_width=True)
                filter_val = st.text_input('Filter by key or value (case-insensitive):', '')
                if filter_val:
                    mask = df.apply(lambda row: row.astype(str).str.contains(filter_val, case=False).any(), axis=1)
                    st.dataframe(df[mask], use_container_width=True)
                # --- IOC Extraction & Enrichment ---
                ioc_candidates = set()
                for val in df.astype(str).values.flatten():
                    t = detect_type(val)
                    if t in ("IP", "Domain"):
                        ioc_candidates.add(val)
                if ioc_candidates:
                    st.markdown('**IOC Enrichment**')
                    enrich_button = st.button('Run IOC Enrichment (JSONL)', key='jsonl_enrich')
                    if enrich_button:
                        # Before any ThreadPoolExecutor usage, extract keys ONCE in main thread
                        # For each enrichment block, do this:

                        # Example for one enrichment block:
                        keys = st.session_state.get('api_keys', {})  # Extract keys ONCE in main thread
                        @lru_cache(maxsize=512)
                        def enrich_all(ioc):
                            result = {"IOC": ioc, "Type": detect_type(ioc)}
                            result.update(enrich_otx(ioc, keys=keys))
                            result.update(enrich_vt(ioc, keys=keys))
                            result.update(enrich_greynoise(ioc, keys=keys))
                            try:
                                from utils.api_clients import enrich_ipinfo
                                result.update(enrich_ipinfo(ioc, keys=keys))
                            except ImportError:
                                pass
                            return result
                        
                        # Parallel enrichment with progress bar
                        progress_bar = st.progress(0)
                        status_text = st.empty()
                        
                        enriched = []
                        ioc_list = list(ioc_candidates)
                        
                        with ThreadPoolExecutor(max_workers=10) as executor:
                            # Submit all tasks
                            future_to_ioc = {executor.submit(enrich_all, ioc): ioc for ioc in ioc_list}
                            
                            # Process completed tasks with progress updates
                            for i, future in enumerate(future_to_ioc):
                                try:
                                    result = future.result()
                                    enriched.append(result)
                                    progress = (i + 1) / len(ioc_list)
                                    progress_bar.progress(progress)
                                    status_text.text(f"Enriching IOCs... {i + 1}/{len(ioc_list)} ({progress:.1%})")
                                except Exception as e:
                                    st.warning(f"Error enriching IOC: {e}")
                                    continue
                        
                        # Clear progress indicators
                        progress_bar.empty()
                        status_text.empty()
                        
                        df_enrich = pd.DataFrame(enriched)
                        
                        # Add navigation links
                        df_enrich['VT'] = df_enrich.apply(lambda row: f"https://www.virustotal.com/gui/search/{row['IOC']}", axis=1)
                        df_enrich['OTX'] = df_enrich.apply(lambda row: f"https://otx.alienvault.com/indicator/{row['Type'].lower()}/{row['IOC']}", axis=1)
                        df_enrich['GN'] = df_enrich.apply(
                            lambda row: f"https://www.greynoise.io/viz/ip/{row['IOC']}" if 'ip' in row['Type'].lower() else None,
                            axis=1
                        )
                        
                        # Define column configuration for links
                        column_config = {
                            "IOC": st.column_config.TextColumn(help="The original IOC (IP, domain, or hash)"),
                            "Type": st.column_config.TextColumn(help="Automatically detected type of the indicator"),
                            "VT": st.column_config.LinkColumn(
                                "VirusTotal",
                                display_text="VT",
                                help="Pivots to the VirusTotal report"
                            ),
                            "OTX": st.column_config.LinkColumn(
                                "OTX",
                                display_text="OTX",
                                help="Pivots to the OTX report"
                            ),
                            "GN": st.column_config.LinkColumn(
                                "GreyNoise",
                                display_text="GN",
                                help="Pivots to the GreyNoise report"
                            ),
                        }
                        
                        # Reorder columns to show links first
                        final_column_order = ['IOC', 'Type', 'VT', 'OTX', 'GN'] + [col for col in df_enrich.columns if col not in ['IOC', 'Type', 'VT', 'OTX', 'GN']]
                        
                        st.dataframe(df_enrich[final_column_order], use_container_width=True, column_config=column_config)
            else:
                data = json.loads(content)
                # --- Stats ---
                if isinstance(data, list) and all(isinstance(x, dict) for x in data):
                    df = pd.DataFrame(data)
                    col1, col2 = st.columns(2)
                    col1.metric('Records', len(df))
                    col2.metric('Unique Keys', len(set().union(*df.columns)))
                    with st.expander('Example Keys'):
                        st.write(list(df.columns)[:10])
                elif isinstance(data, dict):
                    col1, col2 = st.columns(2)
                    col1.metric('Num Keys', len(data.keys()))
                    with col2:
                        with st.expander('Top-level Keys'):
                            st.write(list(data.keys()))
                st.json(data, expanded=False)
                # If array of objects, show as table
                if isinstance(data, list) and all(isinstance(x, dict) for x in data):
                    st.dataframe(df, use_container_width=True)
                    filter_val = st.text_input('Filter by key or value (case-insensitive):', '')
                    if filter_val:
                        mask = df.apply(lambda row: row.astype(str).str.contains(filter_val, case=False).any(), axis=1)
                        st.dataframe(df[mask], use_container_width=True)
                    # --- IOC Extraction & Enrichment ---
                    ioc_candidates = set()
                    for val in df.astype(str).values.flatten():
                        t = detect_type(val)
                        if t in ("IP", "Domain"):
                            ioc_candidates.add(val)
                    if ioc_candidates:
                        st.markdown('**IOC Enrichment**')
                        enrich_button = st.button('Run IOC Enrichment (JSON)', key='json_enrich')
                        if enrich_button:
                            # Before any ThreadPoolExecutor usage, extract keys ONCE in main thread
                            # For each enrichment block, do this:

                            # Example for one enrichment block:
                            keys = st.session_state.get('api_keys', {})  # Extract keys ONCE in main thread
                            @lru_cache(maxsize=512)
                            def enrich_all(ioc):
                                result = {"IOC": ioc, "Type": detect_type(ioc)}
                                result.update(enrich_otx(ioc, keys=keys))
                                result.update(enrich_vt(ioc, keys=keys))
                                result.update(enrich_greynoise(ioc, keys=keys))
                                try:
                                    from utils.api_clients import enrich_ipinfo
                                    result.update(enrich_ipinfo(ioc, keys=keys))
                                except ImportError:
                                    pass
                                return result
                            
                            # Parallel enrichment with progress bar
                            progress_bar = st.progress(0)
                            status_text = st.empty()
                            
                            enriched = []
                            ioc_list = list(ioc_candidates)
                            
                            with ThreadPoolExecutor(max_workers=10) as executor:
                                # Submit all tasks
                                future_to_ioc = {executor.submit(enrich_all, ioc): ioc for ioc in ioc_list}
                                
                                # Process completed tasks with progress updates
                                for i, future in enumerate(future_to_ioc):
                                    try:
                                        result = future.result()
                                        enriched.append(result)
                                        progress = (i + 1) / len(ioc_list)
                                        progress_bar.progress(progress)
                                        status_text.text(f"Enriching IOCs... {i + 1}/{len(ioc_list)} ({progress:.1%})")
                                    except Exception as e:
                                        st.warning(f"Error enriching IOC: {e}")
                                        continue
                            
                            # Clear progress indicators
                            progress_bar.empty()
                            status_text.empty()
                            
                            df_enrich = pd.DataFrame(enriched)
                            
                            # Add navigation links
                            df_enrich['VT'] = df_enrich.apply(lambda row: f"https://www.virustotal.com/gui/search/{row['IOC']}", axis=1)
                            df_enrich['OTX'] = df_enrich.apply(lambda row: f"https://otx.alienvault.com/indicator/{row['Type'].lower()}/{row['IOC']}", axis=1)
                            df_enrich['GN'] = df_enrich.apply(
                                lambda row: f"https://www.greynoise.io/viz/ip/{row['IOC']}" if 'ip' in row['Type'].lower() else None,
                                axis=1
                            )
                            
                            # Define column configuration for links
                            column_config = {
                                "IOC": st.column_config.TextColumn(help="The original IOC (IP, domain, or hash)"),
                                "Type": st.column_config.TextColumn(help="Automatically detected type of the indicator"),
                                "VT": st.column_config.LinkColumn(
                                    "VirusTotal",
                                    display_text="VT",
                                    help="Pivots to the VirusTotal report"
                                ),
                                "OTX": st.column_config.LinkColumn(
                                    "OTX",
                                    display_text="OTX",
                                    help="Pivots to the OTX report"
                                ),
                                "GN": st.column_config.LinkColumn(
                                    "GreyNoise",
                                    display_text="GN",
                                    help="Pivots to the GreyNoise report"
                                ),
                            }
                            
                            # Reorder columns to show links first
                            final_column_order = ['IOC', 'Type', 'VT', 'OTX', 'GN'] + [col for col in df_enrich.columns if col not in ['IOC', 'Type', 'VT', 'OTX', 'GN']]
                            
                            st.dataframe(df_enrich[final_column_order], use_container_width=True, column_config=column_config)
        except Exception as e:
            st.error(f"Error parsing JSON/JSONL: {e}")
    elif file_extension == "xml":
        st.markdown('#### 🗂️ XML Viewer')
        try:
            content = uploaded_file.read().decode('utf-8')
            dom = xml.dom.minidom.parseString(content)
            pretty_xml = dom.toprettyxml()
            # --- Stats ---
            def count_elements(node):
                return 1 + sum(count_elements(child) for child in node.childNodes if child.nodeType == child.ELEMENT_NODE)
            def max_depth(node, depth=0):
                if not node.childNodes:
                    return depth
                return max([max_depth(child, depth+1) for child in node.childNodes if child.nodeType == child.ELEMENT_NODE] or [depth])
            col1, col2, col3 = st.columns(3)
            col1.metric('Root Tag', dom.documentElement.nodeName)
            col2.metric('Num Elements', count_elements(dom.documentElement))
            col3.metric('Max Depth', max_depth(dom.documentElement))
            st.code(pretty_xml, language='xml')
            # Collapsible tree view using st.expander
            def xml_to_tree(node, depth=0, ioc_candidates=None):
                if ioc_candidates is None:
                    ioc_candidates = set()
                if node.nodeType == node.ELEMENT_NODE:
                    with st.expander(f"{'  '*depth}<{node.nodeName}>"):
                        for attr in node.attributes.values() if node.attributes else []:
                            t = detect_type(attr.value)
                            if t in ("IP", "Domain"):
                                ioc_candidates.add(attr.value)
                        for child in node.childNodes:
                            xml_to_tree(child, depth+1, ioc_candidates)
                elif node.nodeType == node.TEXT_NODE and node.data.strip():
                    t = detect_type(node.data.strip())
                    if t in ("IP", "Domain"):
                        ioc_candidates.add(node.data.strip())
                    st.write(f"{'  '*depth}{node.data.strip()}")
                return ioc_candidates
            st.markdown('**Tree View**')
            ioc_candidates = xml_to_tree(dom.documentElement)
            # XPath filter (optional)
            xpath = st.text_input('XPath filter (optional):', '')
            if xpath:
                try:
                    import lxml.etree as LET
                    tree = LET.fromstring(content)
                    results = tree.xpath(xpath)
                    st.write(f"XPath results ({len(results)}):")
                    for r in results:
                        st.write(LET.tostring(r, pretty_print=True, encoding='unicode'))
                except Exception as e:
                    st.error(f"XPath error: {e}")
            # --- IOC Enrichment ---
            if ioc_candidates:
                st.markdown('**IOC Enrichment**')
                enrich_button = st.button('Run IOC Enrichment (XML)', key='xml_enrich')
                if enrich_button:
                    # Before any ThreadPoolExecutor usage, extract keys ONCE in main thread
                    # For each enrichment block, do this:

                    # Example for one enrichment block:
                    keys = st.session_state.get('api_keys', {})  # Extract keys ONCE in main thread
                    @lru_cache(maxsize=512)
                    def enrich_all(ioc):
                        result = {"IOC": ioc, "Type": detect_type(ioc)}
                        result.update(enrich_otx(ioc, keys=keys))
                        result.update(enrich_vt(ioc, keys=keys))
                        result.update(enrich_greynoise(ioc, keys=keys))
                        try:
                            from utils.api_clients import enrich_ipinfo
                            result.update(enrich_ipinfo(ioc, keys=keys))
                        except ImportError:
                            pass
                        return result
                    
                    # Parallel enrichment with progress bar
                    progress_bar = st.progress(0)
                    status_text = st.empty()
                    
                    enriched = []
                    ioc_list = list(ioc_candidates)
                    
                    with ThreadPoolExecutor(max_workers=10) as executor:
                        # Submit all tasks
                        future_to_ioc = {executor.submit(enrich_all, ioc): ioc for ioc in ioc_list}
                        
                        # Process completed tasks with progress updates
                        for i, future in enumerate(future_to_ioc):
                            try:
                                result = future.result()
                                enriched.append(result)
                                progress = (i + 1) / len(ioc_list)
                                progress_bar.progress(progress)
                                status_text.text(f"Enriching IOCs... {i + 1}/{len(ioc_list)} ({progress:.1%})")
                            except Exception as e:
                                st.warning(f"Error enriching IOC: {e}")
                                continue
                    
                    # Clear progress indicators
                    progress_bar.empty()
                    status_text.empty()
                    
                    df_enrich = pd.DataFrame(enriched)
                    
                    # Add navigation links
                    df_enrich['VT'] = df_enrich.apply(lambda row: f"https://www.virustotal.com/gui/search/{row['IOC']}", axis=1)
                    df_enrich['OTX'] = df_enrich.apply(lambda row: f"https://otx.alienvault.com/indicator/{row['Type'].lower()}/{row['IOC']}", axis=1)
                    df_enrich['GN'] = df_enrich.apply(
                        lambda row: f"https://www.greynoise.io/viz/ip/{row['IOC']}" if 'ip' in row['Type'].lower() else None,
                        axis=1
                    )
                    
                    # Define column configuration for links
                    column_config = {
                        "IOC": st.column_config.TextColumn(help="The original IOC (IP, domain, or hash)"),
                        "Type": st.column_config.TextColumn(help="Automatically detected type of the indicator"),
                        "VT": st.column_config.LinkColumn(
                            "VirusTotal",
                            display_text="VT",
                            help="Pivots to the VirusTotal report"
                        ),
                        "OTX": st.column_config.LinkColumn(
                            "OTX",
                            display_text="OTX",
                            help="Pivots to the OTX report"
                        ),
                        "GN": st.column_config.LinkColumn(
                            "GreyNoise",
                            display_text="GN",
                            help="Pivots to the GreyNoise report"
                        ),
                    }
                    
                    # Reorder columns to show links first
                    final_column_order = ['IOC', 'Type', 'VT', 'OTX', 'GN'] + [col for col in df_enrich.columns if col not in ['IOC', 'Type', 'VT', 'OTX', 'GN']]
                    
                    st.dataframe(df_enrich[final_column_order], use_container_width=True, column_config=column_config)
        except Exception as e:
            st.error(f"Error parsing XML: {e}")
    elif file_extension == "csv":
        st.markdown('#### 🗂️ CSV Viewer')
        try:
            df = pd.read_csv(uploaded_file)
            # --- Stats ---
            col1, col2, col3 = st.columns(3)
            col1.metric('Rows', len(df))
            col2.metric('Columns', len(df.columns))
            col3.metric('Missing Values', int(df.isnull().sum().sum()))
            with st.expander('Column Names'):
                st.write(list(df.columns))
            st.dataframe(df, use_container_width=True)
            filter_val = st.text_input('Search/filter CSV:', '')
            if filter_val:
                mask = df.apply(lambda row: row.astype(str).str.contains(filter_val, case=False).any(), axis=1)
                st.dataframe(df[mask], use_container_width=True)
            # --- IOC Extraction & Enrichment ---
            ioc_candidates = set()
            for val in df.astype(str).values.flatten():
                t = detect_type(val)
                if t in ("IP", "Domain"):
                    ioc_candidates.add(val)
            if ioc_candidates:
                st.markdown('**IOC Enrichment**')
                enrich_button = st.button('Run IOC Enrichment (CSV)', key='csv_enrich')
                if enrich_button:
                    # Before any ThreadPoolExecutor usage, extract keys ONCE in main thread
                    # For each enrichment block, do this:

                    # Example for one enrichment block:
                    keys = st.session_state.get('api_keys', {})  # Extract keys ONCE in main thread
                    @lru_cache(maxsize=512)
                    def enrich_all(ioc):
                        result = {"IOC": ioc, "Type": detect_type(ioc)}
                        result.update(enrich_otx(ioc, keys=keys))
                        result.update(enrich_vt(ioc, keys=keys))
                        result.update(enrich_greynoise(ioc, keys=keys))
                        try:
                            from utils.api_clients import enrich_ipinfo
                            result.update(enrich_ipinfo(ioc, keys=keys))
                        except ImportError:
                            pass
                        return result
                    
                    # Parallel enrichment with progress bar
                    progress_bar = st.progress(0)
                    status_text = st.empty()
                    
                    enriched = []
                    ioc_list = list(ioc_candidates)
                    
                    with ThreadPoolExecutor(max_workers=10) as executor:
                        # Submit all tasks
                        future_to_ioc = {executor.submit(enrich_all, ioc): ioc for ioc in ioc_list}
                        
                        # Process completed tasks with progress updates
                        for i, future in enumerate(future_to_ioc):
                            try:
                                result = future.result()
                                enriched.append(result)
                                progress = (i + 1) / len(ioc_list)
                                progress_bar.progress(progress)
                                status_text.text(f"Enriching IOCs... {i + 1}/{len(ioc_list)} ({progress:.1%})")
                            except Exception as e:
                                st.warning(f"Error enriching IOC: {e}")
                                continue
                    
                    # Clear progress indicators
                    progress_bar.empty()
                    status_text.empty()
                    
                    df_enrich = pd.DataFrame(enriched)
                    
                    # Add navigation links
                    df_enrich['VT'] = df_enrich.apply(lambda row: f"https://www.virustotal.com/gui/search/{row['IOC']}", axis=1)
                    df_enrich['OTX'] = df_enrich.apply(lambda row: f"https://otx.alienvault.com/indicator/{row['Type'].lower()}/{row['IOC']}", axis=1)
                    df_enrich['GN'] = df_enrich.apply(
                        lambda row: f"https://www.greynoise.io/viz/ip/{row['IOC']}" if 'ip' in row['Type'].lower() else None,
                        axis=1
                    )
                    
                    # Define column configuration for links
                    column_config = {
                        "IOC": st.column_config.TextColumn(help="The original IOC (IP, domain, or hash)"),
                        "Type": st.column_config.TextColumn(help="Automatically detected type of the indicator"),
                        "VT": st.column_config.LinkColumn(
                            "VirusTotal",
                            display_text="VT",
                            help="Pivots to the VirusTotal report"
                        ),
                        "OTX": st.column_config.LinkColumn(
                            "OTX",
                            display_text="OTX",
                            help="Pivots to the OTX report"
                        ),
                        "GN": st.column_config.LinkColumn(
                            "GreyNoise",
                            display_text="GN",
                            help="Pivots to the GreyNoise report"
                        ),
                    }
                    
                    # Reorder columns to show links first
                    final_column_order = ['IOC', 'Type', 'VT', 'OTX', 'GN'] + [col for col in df_enrich.columns if col not in ['IOC', 'Type', 'VT', 'OTX', 'GN']]
                    
                    st.dataframe(df_enrich[final_column_order], use_container_width=True, column_config=column_config)
        except Exception as e:
            st.error(f"Error parsing CSV: {e}")
    elif file_extension in ["db", "sqlite"]:
        st.markdown('#### 🗂️ Database Viewer')
        with tempfile.NamedTemporaryFile(delete=False, suffix=f'.{file_extension}') as tmpfile:
            tmpfile.write(uploaded_file.read())
            tmpfile.flush()
            db_path = tmpfile.name
        try:
            con = sqlite3.connect(db_path)
            tables = pd.read_sql_query("SELECT name FROM sqlite_master WHERE type='table';", con)['name'].tolist()
            # --- Stats ---
            st.markdown('**Stats**')
            col1, col2 = st.columns(2)
            col1.metric('Num Tables', len(tables))
            with col2:
                with st.expander('Tables'):
                    st.write(tables)
            st.write(f"Tables found: {tables}")
            table = st.selectbox('Select table to view', tables)
            if table:
                df = pd.read_sql_query(f"SELECT * FROM {table} LIMIT 100", con)
                c1, c2 = st.columns(2)
                c1.metric('Rows (preview)', len(df))
                c2.metric('Columns', len(df.columns))
                with st.expander('Column Names'):
                    st.write(list(df.columns))
                st.dataframe(df, use_container_width=True)
            query = st.text_area('Run SQL query (DuckDB syntax supported):', f'SELECT * FROM {table} LIMIT 100')
            if st.button('Run Query'):
                try:
                    duck_con = duckdb.connect()
                    duck_con.execute(f"INSTALL sqlite; LOAD sqlite; ATTACH '{db_path}' AS db;")
                    result = duck_con.execute(query).fetchdf()
                    st.dataframe(result, use_container_width=True)
                except Exception as e:
                    st.error(f"Query error: {e}")
        except Exception as e:
            st.error(f"Error opening database: {e}")
        finally:
            os.unlink(db_path)
    elif file_extension == "bin":
        st.markdown('#### 🗂️ Binary (Hex) Viewer')
        content = uploaded_file.read()
        # --- Stats ---
        st.markdown('**Stats**')
        col1, col2 = st.columns(2)
        col1.metric('File Size (bytes)', len(content))
        col2.metric('Magic Number', binascii.hexlify(content[:8]).decode('ascii').upper())
        def hex_view(data, width=16):
            lines = []
            for i in range(0, len(data), width):
                chunk = data[i:i+width]
                hex_bytes = ' '.join(f'{b:02X}' for b in chunk)
                ascii_bytes = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
                lines.append(f'{i:08X}  {hex_bytes:<{width*3}}  {ascii_bytes}')
            return '\n'.join(lines)
        st.code(hex_view(content), language='text')
        # Magic number detection
        magic = binascii.hexlify(content[:8]).decode('ascii').upper()
        st.write(f"Magic number (first 8 bytes): {magic}")
        search = st.text_input('Search for hex string or ASCII keyword:')
        if search:
            found = False
            if all(c in '0123456789ABCDEFabcdef' for c in search) and len(search) % 2 == 0:
                # Hex search
                if bytes.fromhex(search.lower()) in content:
                    st.success('Hex string found!')
                    found = True
            else:
                if search.encode() in content:
                    st.success('ASCII keyword found!')
                    found = True
            if not found:
                st.warning('Not found.')
    else:
        st.markdown('#### 🗂️ Custom Parser')
        
        # Custom Parser Options
        use_custom_parser = st.checkbox("Enable Custom Parser Mode", value=False, 
                                       help="Parse files with custom record patterns")
        
        if use_custom_parser:
            st.markdown("##### 📝 Parser Configuration")
            
            # Parser Type Selection
            parser_type = st.selectbox(
                "Select Parser Type",
                ["Line-based", "Delimiter-based", "Regex-based", "Multi-line"],
                help="Choose how to parse your file"
            )
            
            # Common options
            skip_lines = st.number_input("Skip header lines", min_value=0, value=0, step=1)
            
            if parser_type == "Line-based":
                st.info("Each line will be treated as a separate record")
                field_separator = st.text_input("Field separator (optional)", value="", 
                                               help="Leave empty to treat each line as a single field")
                field_names = st.text_input("Field names (comma-separated, optional)", 
                                           help="e.g., timestamp,event,source,destination")
                
            elif parser_type == "Delimiter-based":
                delimiter = st.text_input("Record delimiter", value="\n", 
                                         help="Character(s) that separate records")
                field_separator = st.text_input("Field separator", value=",", 
                                               help="Character(s) that separate fields within records")
                field_names = st.text_input("Field names (comma-separated, optional)")
                quote_char = st.text_input("Quote character (optional)", value='"', 
                                          help="Character used to quote fields")
                
            elif parser_type == "Regex-based":
                record_pattern = st.text_input("Record pattern (regex)", 
                                              help="Regex pattern to match complete records. Use capture groups () to extract fields automatically.")
                field_patterns = st.text_area("Field patterns (one per line)", 
                                             help="Optional: Additional regex patterns to extract specific fields. Leave empty to use capture groups from record pattern.")
                field_names = st.text_input("Field names (comma-separated)", 
                                           help="Names for the extracted fields. If empty, will use capture groups from record pattern.")
                
                # Show example for the sample file
                if uploaded_file and uploaded_file.name == "regex_based_sample.txt":
                    st.info("💡 **Example for this file:**\n"
                           "• Record pattern: `\\[([^\\]]+)\\] \\[([^\\]]+)\\] \\[([^\\]]+)\\] (.+)`\n"
                           "• Field names: `timestamp,level,source,message`\n"
                           "• This will extract: timestamp, log level, source IP:port, and the rest as message")
                
                # Show example for multi-line sample file
                if uploaded_file and uploaded_file.name == "multi_line_sample.txt":
                    st.info("💡 **Example for this file:**\n"
                           "• Record start pattern: `=== EVENT START ===`\n"
                           "• Field patterns (copy exactly):\n"
                           "  `Timestamp: (.+)`\n"
                           "  `Event Type: (.+)`\n"
                           "  `Source IP: (.+)`\n"
                           "  `Destination: (.+)`\n"
                           "  `User Agent: (.+)`\n"
                           "  `Status: (.+)`\n"
                           "• Field names: `timestamp,event_type,source_ip,destination,user_agent,status`\n"
                           "• **Important:** Make sure you have exactly 6 field patterns matching your 6 field names!")
                

                
            elif parser_type == "Multi-line":
                record_start_pattern = st.text_input("Record start pattern (regex)", 
                                                    help="Pattern that indicates start of new record")
                field_patterns = st.text_area("Field patterns (one per line)", 
                                             help="Regex patterns to extract fields")
                field_names = st.text_input("Field names (comma-separated)")
            
            # Parse button
            if st.button("Parse File"):
                try:
                    content = uploaded_file.read()
                    
                    # Handle different encodings
                    try:
                        text_content = content.decode('utf-8')
                    except UnicodeDecodeError:
                        try:
                            text_content = content.decode('latin-1')
                        except:
                            st.error("Unable to decode file content. Please check file encoding.")
                            st.stop()
                    
                    lines = text_content.split('\n')
                    
                    # Skip header lines
                    if skip_lines > 0:
                        lines = lines[skip_lines:]
                    
                    records = []
                    
                    if parser_type == "Line-based":
                        for line in lines:
                            if line.strip():
                                if field_separator:
                                    fields = line.split(field_separator)
                                else:
                                    fields = [line.strip()]
                                records.append(fields)
                                
                    elif parser_type == "Delimiter-based":
                        import re
                        # Split by record delimiter
                        record_text = text_content
                        if delimiter != "\n":
                            record_text = text_content.replace('\n', '\\n')
                            records_raw = re.split(re.escape(delimiter), record_text)
                        else:
                            records_raw = lines
                        
                        for record in records_raw:
                            if record.strip():
                                # Handle quoted fields
                                if quote_char:
                                    # Simple quoted field handling
                                    fields = []
                                    current_field = ""
                                    in_quotes = False
                                    i = 0
                                    while i < len(record):
                                        char = record[i]
                                        if char == quote_char:
                                            in_quotes = not in_quotes
                                        elif char == field_separator and not in_quotes:
                                            fields.append(current_field.strip())
                                            current_field = ""
                                        else:
                                            current_field += char
                                        i += 1
                                    fields.append(current_field.strip())
                                else:
                                    fields = record.split(field_separator)
                                records.append(fields)
                                
                    elif parser_type == "Regex-based":
                        import re
                        if record_pattern:
                            # First, find all lines that match the record pattern
                            matching_lines = []
                            for line in lines:
                                if line.strip() and re.match(record_pattern, line):
                                    matching_lines.append(line)
                            
                            field_patterns_list = [p.strip() for p in field_patterns.split('\n') if p.strip()]
                            
                            for line in matching_lines:
                                fields = []
                                
                                # If field patterns are provided, use them
                                if field_patterns_list:
                                    for pattern in field_patterns_list:
                                        match = re.search(pattern, line)
                                        fields.append(match.group(1) if match else "")
                                else:
                                    # If no field patterns, extract capture groups from record pattern
                                    match = re.match(record_pattern, line)
                                    if match:
                                        fields = list(match.groups())
                                    else:
                                        fields = [line.strip()]
                                
                                records.append(fields)
                        else:
                            st.error("Record pattern is required for regex-based parsing")
                            st.stop()
                            

                            
                    elif parser_type == "Multi-line":
                        import re
                        if record_start_pattern:
                            # Split content into records based on start pattern
                            record_sections = re.split(record_start_pattern, text_content)
                            field_patterns_list = [p.strip() for p in field_patterns.split('\n') if p.strip()]
                            
                            for section in record_sections[1:]:  # Skip first empty section
                                if section.strip():
                                    fields = []
                                    # For each field pattern, search within this record section only
                                    for pattern in field_patterns_list:
                                        match = re.search(pattern, section, re.MULTILINE)
                                        if match:
                                            # Extract only the captured group, not the entire match
                                            extracted_value = match.group(1).strip()
                                            fields.append(extracted_value)
                                        else:
                                            fields.append("")
                                    records.append(fields)
                        else:
                            st.error("Record start pattern is required for multi-line parsing")
                            st.stop()
                    
                    # Create DataFrame
                    if records:
                        # Handle field names
                        if field_names:
                            column_names = [name.strip() for name in field_names.split(',')]
                            
                            # Validate field patterns vs field names for multi-line parser
                            if parser_type == "Multi-line":
                                field_patterns_list = [p.strip() for p in field_patterns.split('\n') if p.strip()]
                                if len(field_patterns_list) != len(column_names):
                                    st.warning(f"⚠️ **Mismatch detected:** You have {len(field_patterns_list)} field patterns but {len(column_names)} field names. This may cause parsing issues.")
                                    st.info("💡 **Tip:** Make sure you have the same number of field patterns as field names, or the parser will only extract the first N fields where N is the number of patterns.")
                                
                                # Debug: Show what patterns are being used
                                with st.expander("🔍 Debug: Field Patterns"):
                                    st.write("**Field Patterns:**")
                                    for i, pattern in enumerate(field_patterns_list):
                                        st.write(f"{i+1}. `{pattern}`")
                                    st.write("**Field Names:**")
                                    for i, name in enumerate(column_names):
                                        st.write(f"{i+1}. `{name}`")
                        else:
                            # Generate default column names
                            max_fields = max(len(record) for record in records)
                            if parser_type == "Multi-line":
                                # For multi-line parser, use field1, field2, etc.
                                column_names = [f"field{i+1}" for i in range(max_fields)]
                            elif parser_type == "Regex-based" and record_pattern:
                                # Try to count capture groups in the record pattern
                                import re
                                try:
                                    # Count capture groups in the pattern
                                    group_count = len(re.findall(r'\([^)]*\)', record_pattern))
                                    if group_count > 0:
                                        column_names = [f"Group_{i+1}" for i in range(group_count)]
                                    else:
                                        column_names = [f"Field_{i+1}" for i in range(max_fields)]
                                except:
                                    column_names = [f"Field_{i+1}" for i in range(max_fields)]
                            else:
                                column_names = [f"Field_{i+1}" for i in range(max_fields)]
                        
                        # Pad records to have same number of fields
                        max_fields = max(len(record) for record in records)
                        padded_records = []
                        for record in records:
                            padded_record = record + [''] * (max_fields - len(record))
                            padded_records.append(padded_record)
                        
                        # Safety check: ensure column_names is defined
                        if 'column_names' not in locals():
                            # Fallback: generate default column names
                            column_names = [f"field{i+1}" for i in range(max_fields)]
                        
                        df = pd.DataFrame(padded_records, columns=column_names)
                        
                        # Store parsed data in session state
                        st.session_state.parsed_df = df
                        st.session_state.parsed_file_name = uploaded_file.name
                        
                        # Display results
                        st.success(f"Successfully parsed {len(df)} records with {len(df.columns)} fields")
                        
                except Exception as e:
                    st.error(f"Error parsing file: {e}")
                    st.exception(e)
            
            # Display parsed data if available in session state
            if 'parsed_df' in st.session_state:
                df = st.session_state.parsed_df
                
                # Full data with filters
                st.markdown("##### 📋 Full Dataset")
                filter_val = st.text_input('Search/filter data:', '')
                if filter_val:
                    mask = df.apply(lambda row: row.astype(str).str.contains(filter_val, case=False).any(), axis=1)
                    st.dataframe(df[mask], use_container_width=True)
                else:
                    st.dataframe(df, use_container_width=True)
                
                # IOC Extraction & Enrichment
                ioc_candidates = set()
                for val in df.astype(str).values.flatten():
                    t = detect_type(val)
                    if t in ("IP", "Domain"):
                        ioc_candidates.add(val)
                
                if ioc_candidates:
                    st.markdown('##### 🔎 IOC Enrichment')
                    enrich_button = st.button('Run IOC Enrichment (Custom Parser)')
                    if enrich_button:
                        # Before any ThreadPoolExecutor usage, extract keys ONCE in main thread
                        # For each enrichment block, do this:

                        # Example for one enrichment block:
                        keys = st.session_state.get('api_keys', {})  # Extract keys ONCE in main thread
                        @lru_cache(maxsize=512)
                        def enrich_all(ioc):
                            result = {"IOC": ioc, "Type": detect_type(ioc)}
                            result.update(enrich_otx(ioc, keys=keys))
                            result.update(enrich_vt(ioc, keys=keys))
                            result.update(enrich_greynoise(ioc, keys=keys))
                            try:
                                from utils.api_clients import enrich_ipinfo
                                result.update(enrich_ipinfo(ioc, keys=keys))
                            except ImportError:
                                pass
                            return result
                        
                        # Parallel enrichment with progress bar
                        progress_bar = st.progress(0)
                        status_text = st.empty()
                        
                        enriched = []
                        ioc_list = list(ioc_candidates)
                        
                        with ThreadPoolExecutor(max_workers=10) as executor:
                            # Submit all tasks
                            future_to_ioc = {executor.submit(enrich_all, ioc): ioc for ioc in ioc_list}
                            
                            # Process completed tasks with progress updates
                            for i, future in enumerate(future_to_ioc):
                                try:
                                    result = future.result()
                                    enriched.append(result)
                                    progress = (i + 1) / len(ioc_list)
                                    progress_bar.progress(progress)
                                    status_text.text(f"Enriching IOCs... {i + 1}/{len(ioc_list)} ({progress:.1%})")
                                except Exception as e:
                                    st.warning(f"Error enriching IOC: {e}")
                                    continue
                        
                        # Clear progress indicators
                        progress_bar.empty()
                        status_text.empty()
                        
                        df_enrich = pd.DataFrame(enriched)
                        
                        # Add navigation links
                        df_enrich['VT'] = df_enrich.apply(lambda row: f"https://www.virustotal.com/gui/search/{row['IOC']}", axis=1)
                        df_enrich['OTX'] = df_enrich.apply(lambda row: f"https://otx.alienvault.com/indicator/{row['Type'].lower()}/{row['IOC']}", axis=1)
                        df_enrich['GN'] = df_enrich.apply(
                            lambda row: f"https://www.greynoise.io/viz/ip/{row['IOC']}" if 'ip' in row['Type'].lower() else None,
                            axis=1
                        )
                        
                        # Define column configuration for links
                        column_config = {
                            "IOC": st.column_config.TextColumn(help="The original IOC (IP, domain, or hash)"),
                            "Type": st.column_config.TextColumn(help="Automatically detected type of the indicator"),
                            "VT": st.column_config.LinkColumn(
                                "VirusTotal",
                                display_text="VT",
                                help="Pivots to the VirusTotal report"
                            ),
                            "OTX": st.column_config.LinkColumn(
                                "OTX",
                                display_text="OTX",
                                help="Pivots to the OTX report"
                            ),
                            "GN": st.column_config.LinkColumn(
                                "GreyNoise",
                                display_text="GN",
                                help="Pivots to the GreyNoise report"
                            ),
                        }
                        
                        # Reorder columns to show links first
                        final_column_order = ['IOC', 'Type', 'VT', 'OTX', 'GN'] + [col for col in df_enrich.columns if col not in ['IOC', 'Type', 'VT', 'OTX', 'GN']]
                        
                        st.dataframe(df_enrich[final_column_order], use_container_width=True, column_config=column_config)
        else:
            # Original fallback viewer
            st.markdown('#### 🗂️ Fallback Viewer')
            try:
                content = uploaded_file.read()
                # --- Stats ---
                st.markdown('**Stats**')
                col1, col2 = st.columns(2)
                col1.metric('File Size (bytes)', len(content))
                try:
                    text = content.decode('utf-8')
                    col2.metric('Lines', text.count('\n')+1)
                    with st.expander('Characters'):
                        st.write(len(text))
                    st.text_area('Text Preview', text, height=400)
                except Exception:
                    st.warning('Unsupported file type – opened in fallback mode (hex view below)')
                    import binascii
                    def hex_view(data, width=16):
                        lines = []
                        for i in range(0, len(data), width):
                            chunk = data[i:i+width]
                            hex_bytes = ' '.join(f'{b:02X}' for b in chunk)
                            ascii_bytes = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
                            lines.append(f'{i:08X}  {hex_bytes:<{width*3}}  {ascii_bytes}')
                        return '\n'.join(lines)
                    st.code(hex_view(content), language='text')
            except Exception as e:
                st.error(f"Error opening file: {e}")
else:
    st.info("Please upload a file to proceed.") 