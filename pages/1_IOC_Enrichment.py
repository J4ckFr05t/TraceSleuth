import streamlit as st
import pandas as pd
import pydeck as pdk
from utils.api_clients import detect_type, enrich_otx, enrich_vt, enrich_greynoise, enrich_ipinfo
from concurrent.futures import ThreadPoolExecutor
import plotly.graph_objects as go

def shorten_labels(label, max_len=20):
    """Truncates long labels."""
    if len(str(label)) > max_len:
        return str(label)[:max_len-3] + '...'
    return str(label)

def render_donut_chart(df, count_col, label_col, title, color_scheme='blues', colors=None):
    """Helper function to create consistent donut charts with proper label handling"""
    # Shorten labels if needed
    df[label_col] = df[label_col].astype(str).apply(shorten_labels)
    
    # Calculate percentages for the labels
    total = df[count_col].sum()
    df['percentage'] = (df[count_col] / total * 100).round(1)
    df['label'] = df[label_col] + ' (' + df['percentage'].astype(str) + '%)'
    
    # Get colors
    if colors is None:
        # Define color schemes
        color_schemes = {
            'blues': ['#1f77b4', '#aec7e8', '#ff7f0e', '#ffbb78', '#2ca02c'],
            'greens': ['#2ca02c', '#98df8a', '#d62728', '#ff9896', '#9467bd']
        }
        
        # Get colors based on scheme
        chart_colors = color_schemes.get(color_scheme, color_schemes['blues'])
        # Repeat colors if needed
        chart_colors = chart_colors * (len(df) // len(chart_colors) + 1)
        chart_colors = chart_colors[:len(df)]
    else:
        chart_colors = colors
    
    # Create the donut chart using Plotly
    fig = go.Figure(data=[go.Pie(
        labels=df[label_col],  # Use original labels for legend
        values=df[count_col],
        text=df['label'], # Use combined labels for text on slices
        hole=.5,
        textinfo='text', # Show the 'text' property on slices
        hovertemplate='%{label}<br>Count: %{value}<br>Percentage: %{percent:.1%}<extra></extra>',
        marker=dict(colors=chart_colors, line=dict(color='black', width=3))
    )])
    
    fig.update_traces(
        textposition='outside'
    )
    
    fig.update_layout(
        title_text=title,
        showlegend=True,
        legend=dict(
            orientation="v",
            yanchor="middle",
            y=0.5,
            xanchor="left",
            x=1.02
        ),
        annotations=[dict(text=f'{total}', x=0.5, y=0.5, font_size=20, showarrow=False)],
        margin=dict(t=50, b=50, l=50, r=50)
    )
    
    return fig

# --- DATA LOADING ---
@st.cache_data
def load_country_data():
    """Loads and caches the country coordinate data."""
    try:
        df = pd.read_csv('static/country-coord.csv')
        df['Alpha-2 code'] = df['Alpha-2 code'].str.strip()
        df['Alpha-3 code'] = df['Alpha-3 code'].str.strip()
        return df
    except FileNotFoundError:
        st.error("Error: `static/country-coord.csv` not found. Geolocation features will be limited.")
        return None

country_coords = load_country_data()

# --- SESSION STATE ---
if 'results_df' not in st.session_state:
    st.session_state.results_df = None
if 'user_input' not in st.session_state:
    st.session_state.user_input = ""

# --- MAIN APP ---

st.title("🔬 IOC Enrichment Engine")
st.markdown("Paste IOCs below or upload a CSV file to enrich them with threat intelligence data.")

# --- INPUT ---
ioc_input_area = st.text_area(
    "Enter IOCs",
    value=st.session_state.user_input,
    height=150,
    placeholder="Enter one IOC per line (IPs, domains, hashes)",
    key="ioc_text_area"
)
uploaded_file = st.file_uploader("Upload CSV", type=["csv"])


# --- PROCESSING & ENRICHMENT ---
if st.button("🧠 Enrich IOCs"):
    ioc_list = []
    
    # Determine IOCs from input
    if uploaded_file:
        try:
            df = pd.read_csv(uploaded_file)
            ioc_list = df.iloc[:, 0].dropna().astype(str).tolist()
            st.session_state.user_input = "\n".join(ioc_list)
            # Rerun to update the text area with the content of the uploaded file
            st.rerun()
        except Exception as e:
            st.error(f"Error reading CSV file: {e}")
            ioc_list = [] # Ensure list is empty on error
            
    elif ioc_input_area:
        ioc_list = list(set(i.strip() for i in ioc_input_area.splitlines() if i.strip()))
        st.session_state.user_input = ioc_input_area
    
    # If we have IOCs, enrich them
    if ioc_list:
        with st.spinner(f"Enriching {len(ioc_list)} IOCs... This may take a moment."):
            results = []

            def enrich(ioc):
                result = {
                    "IOC": ioc,
                    "Type": detect_type(ioc),
                }
                result.update(enrich_otx(ioc))
                result.update(enrich_vt(ioc))
                result.update(enrich_greynoise(ioc))
                result.update(enrich_ipinfo(ioc))
                return result

            with ThreadPoolExecutor(max_workers=10) as executor:
                enriched = list(executor.map(enrich, ioc_list))

            # Create a more user-friendly DataFrame with better column names
            df_results = pd.DataFrame(enriched)
            
            # Rename columns for better display
            column_mapping = {
                'IOC': 'Indicator',
                'Type': 'Type',
                'OTX_Pulse_Count': 'OTX Pulse Count',
                'OTX_Malicious': 'OTX Malicious',
                'OTX_Tags': 'OTX Tags',
                'OTX_Country': 'OTX Country',
                'VT_Malicious': 'VT Malicious',
                'VT_Suspicious': 'VT Suspicious',
                'VT_Tags': 'VT Tags',
                'GN_Classification': 'GN Classification',
                'GN_Name': 'GN Name',
                'GN_Tags': 'GN Tags',
                'IP_Country': 'Country Code', # Will be replaced by full name
                'IP_ASN': 'ASN'
            }
            
            df_display = df_results.rename(columns=column_mapping)
            
            # Map country codes to names and ISO-3 codes
            if country_coords is not None:
                country_map = country_coords.set_index('Alpha-2 code')['Country'].to_dict()
                iso3_map = country_coords.set_index('Alpha-2 code')['Alpha-3 code'].to_dict()
                df_display['Country'] = df_display['Country Code'].map(country_map).fillna('-')
                df_display['Country ISO3'] = df_display['Country Code'].map(iso3_map).fillna('-')
            else:
                df_display['Country'] = df_display['Country Code'] # Fallback
                df_display['Country ISO3'] = df_display['Country Code'] # Fallback
                
            # Add severity column based on threat indicators
            def calculate_severity(row):
                otx_malicious = row['OTX Malicious'] if row['OTX Malicious'] != '-' else False
                vt_malicious = row['VT Malicious'] if row['VT Malicious'] != '-' else 0
                vt_suspicious = row['VT Suspicious'] if row['VT Suspicious'] != '-' else 0
                gn_class = row.get('GN Classification', 'unknown').lower()

                if otx_malicious or vt_malicious > 5 or gn_class == 'malicious':
                    return "High"
                elif vt_malicious > 0 or vt_suspicious > 0 or gn_class == 'benign':
                    return "Medium"
                else:
                    return "Low"
            
            df_display['Threat Level'] = df_display.apply(calculate_severity, axis=1)
            
            # Add pivot links
            df_display['VT'] = df_display.apply(lambda row: f"https://www.virustotal.com/gui/search/{row['Indicator']}", axis=1)
            df_display['OTX'] = df_display.apply(lambda row: f"https://otx.alienvault.com/indicator/{row['Type'].lower()}/{row['Indicator']}", axis=1)
            df_display['GN'] = df_display.apply(
                lambda row: f"https://www.greynoise.io/viz/ip/{row['Indicator']}" if 'ip' in row['Type'].lower() else None,
                axis=1
            )
            
            st.session_state.results_df = df_display
            
    else:
        # Clear previous results if button is clicked with no new input
        st.session_state.results_df = None
        st.warning("Please paste IOCs or upload a CSV file to begin enrichment.")


# --- DISPLAY RESULTS ---
if st.session_state.results_df is not None:
    df_display = st.session_state.results_df
    
    # Summary statistics - Stock Market Theme
    total_iocs = len(df_display)
    high_threat = len(df_display[df_display['Threat Level'] == 'High'])
    medium_threat = len(df_display[df_display['Threat Level'] == 'Medium'])
    low_threat = len(df_display[df_display['Threat Level'] == 'Low'])
    
    # Stock market style metrics
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.markdown(f"""
        <div style="
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 15px;
            border-radius: 8px;
            text-align: center;
            color: white;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        ">
            <h4 style="margin: 0; font-size: 14px;">TOTAL IOCs</h4>
            <h2 style="margin: 5px 0; font-size: 28px; font-weight: bold;">{total_iocs}</h2>
            <p style="margin: 0; font-size: 12px;">&nbsp;</p>
        </div>
        """, unsafe_allow_html=True)
    
    with col2:
        high_percent = f"{high_threat/total_iocs*100:.1f}%" if total_iocs > 0 else "0%"
        st.markdown(f"""
        <div style="
            background: linear-gradient(135deg, #ff6b6b 0%, #ee5a24 100%);
            padding: 15px;
            border-radius: 8px;
            text-align: center;
            color: white;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        ">
            <h4 style="margin: 0; font-size: 14px;">HIGH THREAT</h4>
            <h2 style="margin: 5px 0; font-size: 28px; font-weight: bold;">{high_threat}</h2>
            <p style="margin: 0; font-size: 12px;">{high_percent}</p>
        </div>
        """, unsafe_allow_html=True)
    
    with col3:
        medium_percent = f"{medium_threat/total_iocs*100:.1f}%" if total_iocs > 0 else "0%"
        st.markdown(f"""
        <div style="
            background: linear-gradient(135deg, #feca57 0%, #ff9ff3 100%);
            padding: 15px;
            border-radius: 8px;
            text-align: center;
            color: white;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        ">
            <h4 style="margin: 0; font-size: 14px;">MEDIUM THREAT</h4>
            <h2 style="margin: 5px 0; font-size: 28px; font-weight: bold;">{medium_threat}</h2>
            <p style="margin: 0; font-size: 12px;">{medium_percent}</p>
        </div>
        """, unsafe_allow_html=True)
    
    with col4:
        low_percent = f"{low_threat/total_iocs*100:.1f}%" if total_iocs > 0 else "0%"
        st.markdown(f"""
        <div style="
            background: linear-gradient(135deg, #48cae4 0%, #00b4d8 100%);
            padding: 15px;
            border-radius: 8px;
            text-align: center;
            color: white;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        ">
            <h4 style="margin: 0; font-size: 14px;">LOW THREAT</h4>
            <h2 style="margin: 5px 0; font-size: 28px; font-weight: bold;">{low_threat}</h2>
            <p style="margin: 0; font-size: 12px;">{low_percent}</p>
        </div>
        """, unsafe_allow_html=True)
    
    st.subheader("IOC Type Distribution")

    # Determine color for each type based on the highest threat level
    threat_order = pd.CategoricalDtype(['Low', 'Medium', 'High'], ordered=True)
    df_display['Threat Level Category'] = df_display['Threat Level'].astype(threat_order)
    
    type_summary_df = df_display.groupby('Type').agg(
        Count=('Type', 'count'),
        Max_Threat=('Threat Level Category', 'max')
    ).reset_index()

    threat_color_map = {'High': 'red', 'Medium': 'orange', 'Low': 'green'}
    type_summary_df['color'] = type_summary_df['Max_Threat'].map(threat_color_map)

    fig = render_donut_chart(
        type_summary_df, 
        'Count', 
        'Type', 
        'IOC Type Distribution', 
        colors=type_summary_df['color'].tolist()
    )
    st.plotly_chart(fig, use_container_width=True)

    # Top Tags Analysis
    st.subheader("🏷️ Top Tags Analysis")
    
    # Collect all tags from all sources
    all_tags = []
    
    # Process GN Tags
    for _, row in df_display.iterrows():
        gn_tags = row.get('GN Tags', '-')
        if gn_tags != '-':
            tags = [tag.strip() for tag in gn_tags.split(',') if tag.strip()]
            all_tags.extend([(tag, 'GreyNoise') for tag in tags])
    
    # Process VT Tags
    for _, row in df_display.iterrows():
        vt_tags = row.get('VT Tags', '-')
        if vt_tags != '-':
            tags = [tag.strip() for tag in vt_tags.split(',') if tag.strip()]
            all_tags.extend([(tag, 'VirusTotal') for tag in tags])
    
    # Process OTX Tags
    for _, row in df_display.iterrows():
        otx_tags = row.get('OTX Tags', '-')
        if otx_tags != '-':
            tags = [tag.strip() for tag in otx_tags.split(',') if tag.strip()]
            all_tags.extend([(tag, 'OTX') for tag in tags])
    
    if all_tags:
        # Count tag occurrences
        tag_counts = {}
        for tag, source in all_tags:
            if tag not in tag_counts:
                tag_counts[tag] = {'count': 0, 'sources': set()}
            tag_counts[tag]['count'] += 1
            tag_counts[tag]['sources'].add(source)
        
        # Convert to DataFrame for visualization
        tag_data = []
        for tag, data in tag_counts.items():
            tag_data.append({
                'Tag': tag,
                'Count': data['count'],
                'Sources': ', '.join(sorted(data['sources']))
            })
        
        tag_df = pd.DataFrame(tag_data)
        tag_df = tag_df.sort_values('Count', ascending=False).head(20)  # Top 20 tags
        
        # Define a function to get source attributes
        def get_source_attributes(sources_str):
            is_gn = 'GreyNoise' in sources_str
            is_vt = 'VirusTotal' in sources_str
            is_otx = 'OTX' in sources_str
            
            if is_gn and is_vt and is_otx:
                return 'All Sources (GN + VT + OTX)', '#ff6b6b'
            elif is_gn and is_vt:
                return 'GreyNoise + VirusTotal', '#feca57'
            elif is_gn and is_otx:
                return 'GreyNoise + OTX', '#48cae4'
            elif is_vt and is_otx:
                return 'VirusTotal + OTX', '#ff9ff3'
            elif is_gn:
                return 'GreyNoise Only', '#2ca02c'
            elif is_vt:
                return 'VirusTotal Only', '#d62728'
            else:  # OTX only
                return 'OTX Only', '#9467bd'

        # Apply the function to create new columns for legend label and color
        attributes = tag_df['Sources'].apply(get_source_attributes).apply(pd.Series)
        attributes.columns = ['LegendLabel', 'Color']
        tag_df = pd.concat([tag_df, attributes], axis=1)
        
        # Check if we have fewer than 5 distinct tags for donut chart
        if len(tag_df) < 5:
            # Use donut chart for fewer than 5 tags
            fig = render_donut_chart(
                tag_df, 
                'Count', 
                'Tag', 
                'Top Tags by Frequency',
                colors=tag_df['Color'].tolist()
            )
            st.plotly_chart(fig, use_container_width=True)
            
            # Show legend below the chart
            st.markdown("##### Tag Sources")
            unique_legends = tag_df[['LegendLabel', 'Color']].drop_duplicates()
            for _, row in unique_legends.iterrows():
                label = row['LegendLabel']
                color = row['Color']
                st.markdown(
                    f'<div style="display: flex; align-items: center; margin-bottom: 5px;">'
                    f'<div style="width: 12px; height: 12px; background-color: {color}; border-radius: 50%; margin-right: 10px;"></div>'
                    f'<span>{label}</span>'
                    f'</div>',
                    unsafe_allow_html=True
                )
        else:
            # Use horizontal bar chart for 5 or more tags
            fig = go.Figure()
            
            # Reverse the order for horizontal bar chart to show highest count at top
            fig.add_trace(go.Bar(
                y=tag_df['Tag'].tolist()[::-1],
                x=tag_df['Count'].tolist()[::-1],
                orientation='h',
                marker=dict(color=tag_df['Color'].tolist()[::-1]),  # Use the new color column
                text=tag_df['Count'].tolist()[::-1],
                textposition='auto',
                hovertemplate='<b>%{y}</b><br>Count: %{x}<br>Sources: %{customdata}<extra></extra>',
                customdata=tag_df['Sources'].tolist()[::-1]
            ))
            
            fig.update_layout(
                title_text="Top Tags by Frequency",
                xaxis_title="Count",
                yaxis_title="Tags",
                height=max(400, len(tag_df) * 25),
                showlegend=False,
                margin=dict(t=50, b=50, l=200, r=50)
            )
            
            # Create side-by-side layout: chart on left, legend on right
            chart_col, legend_col = st.columns([3, 1])
            
            with chart_col:
                st.plotly_chart(fig, use_container_width=True)
            
            with legend_col:

                # Get unique legend items from the dataframe, preserving order
                unique_legends = tag_df[['LegendLabel', 'Color']].drop_duplicates()

                for _, row in unique_legends.iterrows():
                    label = row['LegendLabel']
                    color = row['Color']
                    st.markdown(
                        f'<div style="display: flex; align-items: center; margin-bottom: 5px;">'
                        f'<div style="width: 12px; height: 12px; background-color: {color}; border-radius: 50%; margin-right: 10px;"></div>'
                        f'<span>{label}</span>'
                        f'</div>',
                        unsafe_allow_html=True
                    )
        
    else:
        st.info("No tags found in the enriched data. This could be due to limited threat intelligence data for the provided IOCs.")


    # Geolocation Analysis
    st.subheader("🌍 Geolocation")
    geo_df = df_display[(df_display['Country ISO3'] != '-') & (df_display['Type'] == 'IP')].copy()

    if not geo_df.empty and country_coords is not None:
        # Get counts for each country
        country_counts = geo_df.groupby(['Country', 'Country ISO3']).size().reset_index(name='count')

        # Get coordinates from the lookup table
        country_coords_subset = country_coords[['Alpha-3 code', 'Latitude (average)', 'Longitude (average)']].copy()
        country_coords_subset.rename(columns={
            'Alpha-3 code': 'Country ISO3',
            'Latitude (average)': 'lat',
            'Longitude (average)': 'lon'
        }, inplace=True)
        
        # Merge counts with coordinates
        map_data = pd.merge(country_counts, country_coords_subset, on='Country ISO3')
        
        if not map_data.empty:
            # Configure pydeck layer for bubble map
            layer = pdk.Layer(
                "ScatterplotLayer",
                data=map_data,
                get_position='[lon, lat]',
                get_color='[0, 191, 255, 180]',  # Using a bright blue for dark mode
                get_radius='count * 45000 + 20000', # Further increase radius for better visibility
                pickable=True,
                radius_min_pixels=7, # Increase min radius
                radius_max_pixels=80, # Increase max radius
            )

            # Configure pydeck view for a flat, global map
            view_state = pdk.ViewState(
                latitude=20, # Center more on populated areas
                longitude=0,
                zoom=1.2, # Zoom in more to prevent world wrapping
                pitch=0, # Ensures the map is flat
            )
            
            # Tooltip configuration for dark mode
            tooltip = {
                "html": "<b>{Country}</b><br/><b>IOCs:</b> {count}",
                "style": {
                    "backgroundColor": "#272733",
                    "color": "white",
                    "border-radius": "5px",
                    "padding": "5px",
                    "border": "1px solid #fff"
                }
            }

            # Render the pydeck map in dark mode
            st.pydeck_chart(pdk.Deck(
                map_provider='carto',
                map_style='dark',
                initial_view_state=view_state,
                layers=[layer],
                tooltip=tooltip
            ))
        else:
            st.info("Could not map geolocation data to coordinates.")

    else:
        st.info("No geolocation data available for the provided IOCs (IP addresses).")

    # ASN Distribution Analysis
    st.subheader("📡 Top ASNs by IOC Count")
    asn_df = df_display[df_display['ASN'].notna() & (df_display['ASN'] != '-')].copy()

    if not asn_df.empty:
        asn_counts = asn_df['ASN'].value_counts().reset_index()
        asn_counts.columns = ['ASN', 'Count']
        top_asns = asn_counts.head(20)

        # Check if we have fewer than 5 distinct ASNs for donut chart
        if len(top_asns) < 5:
            # Use donut chart for fewer than 5 ASNs
            fig_asn = render_donut_chart(
                top_asns, 
                'Count', 
                'ASN', 
                'Top ASNs by IOC Count'
            )
            st.plotly_chart(fig_asn, use_container_width=True)
        else:
            # Use horizontal bar chart for 5 or more ASNs
            fig_asn = go.Figure(go.Bar(
                y=top_asns['ASN'].astype(str)[::-1],
                x=top_asns['Count'][::-1],
                orientation='h',
                marker=dict(color='#667eea'),
                text=top_asns['Count'][::-1],
                textposition='auto',
                hovertemplate='<b>%{y}</b><br>Count: %{x}<extra></extra>'
            ))

            fig_asn.update_layout(
                title_text="Top 20 ASNs by IOC Count",
                xaxis_title="Number of IOCs",
                yaxis_title="Autonomous System Number (ASN)",
                height=max(400, len(top_asns) * 25),
                showlegend=False,
                margin=dict(t=50, b=50, l=250, r=50)
            )

            st.plotly_chart(fig_asn, use_container_width=True)
    else:
        st.info("No ASN data available for the provided IOCs.")

    # Display results with better formatting
    st.subheader("Enrichment Results")
    
    # Define column configuration for links
    column_config = {
        "Indicator": st.column_config.TextColumn(help="The original IOC (IP, domain, or hash)"),
        "Type": st.column_config.TextColumn(help="Automatically detected type of the indicator"),
        "Threat Level": st.column_config.TextColumn(help="Overall threat assessment based on all sources"),
        "ASN": st.column_config.TextColumn(help="Autonomous System Number of the IP address"),
        "Country": st.column_config.TextColumn(help="Country associated with the IP address"),
        "OTX Country": st.column_config.TextColumn(help="Country associated with the IOC in OTX"),
        "OTX Pulse Count": st.column_config.NumberColumn(help="Number of threat intelligence reports in AlienVault OTX"),
        "OTX Malicious": st.column_config.CheckboxColumn(help="Whether this IOC is flagged as malicious in OTX"),
        "OTX Tags": st.column_config.TextColumn(help="Tags from OTX threat intelligence pulses"),
        "VT Malicious": st.column_config.NumberColumn(help="Number of antivirus engines flagging as malicious"),
        "VT Suspicious": st.column_config.NumberColumn(help="Number of antivirus engines flagging as suspicious"),
        "VT Tags": st.column_config.TextColumn(help="Threat classifications from VirusTotal antivirus engines"),
        "GN Classification": st.column_config.TextColumn(help="GreyNoise classification (malicious, benign, unknown)"),
        "GN Name": st.column_config.TextColumn(help="GreyNoise threat name/description"),
        "GN Tags": st.column_config.TextColumn(help="Tags from GreyNoise threat intelligence"),
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

    # Reorder columns for final display
    final_column_order = ['Indicator', 'Type', 'VT', 'OTX', 'GN', 'Threat Level', 'ASN', 'Country', 'OTX Country', 'OTX Pulse Count', 'OTX Malicious', 'OTX Tags', 'VT Malicious', 'VT Suspicious', 'VT Tags', 'GN Classification', 'GN Name', 'GN Tags']

    # Display the dataframe with custom styling
    st.dataframe(
        df_display[final_column_order],
        use_container_width=True,
        hide_index=True,
        column_config=column_config
    )
    
    # Download functionality
    csv = df_display.to_csv(index=False).encode('utf-8')
    st.download_button(
        "📥 Download Enriched Data (CSV)", 
        data=csv, 
        file_name="ioc_enriched.csv", 
        mime='text/csv',
        help="Download the complete enrichment results including all raw data"
    )
    
else:
    st.warning("Please paste IOCs or upload a CSV file to begin enrichment.")
    
    # Add helpful examples
    with st.expander("💡 Example IOCs"):
        st.markdown("""
        **IP Addresses:**
        ```
        23.228.203.130
        185.177.72.107
        ```
        
        **Domains:**
        ```
        bill.microsoftbuys.com
        dnsupdate.dns2.us
        ```
        
        **File Hashes (MD5/SHA256):**
        ```
        2183AE45ADEF97500A26DBBF69D910B82BFE721A
        255F54DE241A3D12DEBAD2DF47BAC5601895E458
        ```
        """)