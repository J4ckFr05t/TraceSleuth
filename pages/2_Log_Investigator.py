import streamlit as st
import pandas as pd
import xml.etree.ElementTree as ET
from io import BytesIO
import tempfile
from config.high_value_events import DEFAULT_HIGH_VALUE_EVENTS
import altair as alt
from utils.api_clients import detect_type, enrich_otx, enrich_vt, enrich_greynoise
from functools import lru_cache

try:
    from Evtx.Evtx import Evtx
except ImportError:
    Evtx = None
    st.warning("python-evtx is not installed. Please install it to parse .evtx files.")

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

    if file_extension == "evtx":
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
                from collections import defaultdict, deque
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
                @lru_cache(maxsize=512)
                def enrich_all(ioc):
                    otx = enrich_otx(ioc)
                    vt = enrich_vt(ioc)
                    gn = enrich_greynoise(ioc)
                    return otx, vt, gn

                def is_ioc_hit(ioc):
                    otx, vt, gn = enrich_all(ioc)
                    if otx.get('OTX_Malicious') is True:
                        return True
                    if isinstance(vt.get('VT_Malicious'), int) and vt.get('VT_Malicious', 0) > 0:
                        return True
                    if str(gn.get('GN_Classification', '')).lower() == 'malicious':
                        return True
                    return False

                # For each row, scan all fields for IOCs and set IOC_Hit if any are flagged
                for idx, row in df.iterrows():
                    ioc_found = False
                    for value in row.values:
                        if not isinstance(value, str):
                            continue
                        ioc_type = detect_type(value)
                        if ioc_type in ("IP", "Hash", "Domain"):
                            try:
                                if is_ioc_hit(value):
                                    ioc_found = True
                                    break
                            except Exception as e:
                                continue
                    df.at[idx, 'IOC_Hit'] = ioc_found
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
                        if 'HTTP' in proto and hasattr(pkt, 'http'):
                            host = getattr(pkt.http, 'host', None)
                            uri = getattr(pkt.http, 'request_full_uri', None)
                            user_agent = getattr(pkt.http, 'user_agent', None)
                        if 'DNS' in proto and hasattr(pkt, 'dns'):
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
                    # --- Protocol Pie Chart ---
                    st.markdown('#### 🥧 Protocol Distribution')
                    proto_counts = filtered_df['Protocol'].value_counts().reset_index()
                    proto_counts.columns = ['Protocol', 'Count']
                    pie = alt.Chart(proto_counts).mark_arc(innerRadius=40).encode(
                        theta=alt.Theta(field='Count', type='quantitative'),
                        color=alt.Color(field='Protocol', type='nominal'),
                        tooltip=['Protocol', 'Count']
                    ).properties(height=300)
                    st.altair_chart(pie, use_container_width=True)
                    # --- Source-Destination Graph (Optional) ---
                    st.markdown('#### 🌐 Source-Destination Graph (Experimental)')
                    import networkx as nx
                    import plotly.graph_objects as go
                    G = nx.DiGraph()
                    for _, row in filtered_df.iterrows():
                        if row['Source IP'] and row['Destination IP']:
                            G.add_edge(row['Source IP'], row['Destination IP'])
                    if G.number_of_edges() > 0:
                        pos = nx.spring_layout(G, k=0.5, iterations=20)
                        edge_x = []
                        edge_y = []
                        for src, dst in G.edges():
                            x0, y0 = pos[src]
                            x1, y1 = pos[dst]
                            edge_x += [x0, x1, None]
                            edge_y += [y0, y1, None]
                        edge_trace = go.Scatter(x=edge_x, y=edge_y, line=dict(width=0.5, color='#888'), hoverinfo='none', mode='lines')
                        node_x = []
                        node_y = []
                        node_text = []
                        for node in G.nodes():
                            x, y = pos[node]
                            node_x.append(x)
                            node_y.append(y)
                            node_text.append(str(node))
                        node_trace = go.Scatter(x=node_x, y=node_y, mode='markers+text', text=node_text, textposition='top center', marker=dict(size=10, color='skyblue'), hoverinfo='text')
                        fig = go.Figure(data=[edge_trace, node_trace], layout=go.Layout(
                            showlegend=False,
                            hovermode='closest',
                            margin=dict(b=20,l=5,r=5,t=40),
                            xaxis=dict(showgrid=False, zeroline=False),
                            yaxis=dict(showgrid=False, zeroline=False),
                            title='Source-Destination Communication Graph'
                        ))
                        st.plotly_chart(fig, use_container_width=True)
                    else:
                        st.info('Not enough data for a source-destination graph.')
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
                        st.write(f"Enriching {len(ioc_list)} unique IOCs (IPs/domains)...")
                        from concurrent.futures import ThreadPoolExecutor
                        @lru_cache(maxsize=512)
                        def enrich_all(ioc):
                            result = {"IOC": ioc, "Type": detect_type(ioc)}
                            result.update(enrich_otx(ioc))
                            result.update(enrich_vt(ioc))
                            result.update(enrich_greynoise(ioc))
                            # Optionally add enrich_ipinfo if available
                            try:
                                from utils.api_clients import enrich_ipinfo
                                result.update(enrich_ipinfo(ioc))
                            except ImportError:
                                pass
                            return result
                        with st.spinner("Enriching IOCs, please wait..."):
                            with ThreadPoolExecutor(max_workers=10) as executor:
                                enriched = list(executor.map(enrich_all, ioc_list))
                        df_enrich = pd.DataFrame(enriched)
                        # Display enrichment results
                        st.markdown('##### IOC Enrichment Results')
                        st.dataframe(df_enrich, use_container_width=True)
                    else:
                        st.info('No valid IPs or domains found for enrichment.')
            except Exception as e:
                st.error(f"Error parsing PCAP: {e}")
else:
    st.info("Please upload a file to proceed.") 