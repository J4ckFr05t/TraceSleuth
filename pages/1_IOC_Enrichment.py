import streamlit as st
import pandas as pd
from utils.api_clients import detect_type, enrich_otx, enrich_vt
from utils.api_clients import detect_type, enrich_otx, enrich_vt, enrich_greynoise
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

st.title("🔬 IOC Enrichment Engine")
st.markdown("Paste IOCs below or upload a CSV file to enrich them with threat intelligence data.")

# --- INPUT ---
ioc_input = st.text_area("Enter IOCs", height=150, placeholder="Enter one IOC per line (IPs, domains, hashes)")
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
        result.update(enrich_greynoise(ioc))
        print(result)
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
        'VT_Malicious': 'VT Malicious',
        'VT_Suspicious': 'VT Suspicious',
        'GN_Classification': 'GN Classification',
        'GN_Name': 'GN Name',
        'GN_Tags': 'GN Tags'
    }
    
    df_display = df_results.rename(columns=column_mapping)
    
    # Add severity column based on threat indicators
    def calculate_severity(row):
        otx_malicious = row['OTX Malicious'] if row['OTX Malicious'] != '-' else False
        vt_malicious = row['VT Malicious'] if row['VT Malicious'] != '-' else 0
        vt_suspicious = row['VT Suspicious'] if row['VT Suspicious'] != '-' else 0
        
        if otx_malicious or vt_malicious > 5:
            return "High"
        elif vt_malicious > 0 or vt_suspicious > 0:
            return "Medium"
        else:
            return "Low"
    
    df_display['Threat Level'] = df_display.apply(calculate_severity, axis=1)
    
    # Reorder columns for better presentation
    column_order = ['Indicator', 'Type', 'Threat Level', 'OTX Pulse Count', 'OTX Malicious', 'VT Malicious', 'VT Suspicious', 'GN Classification', 'GN Name', 'GN Tags']
    df_display = df_display[column_order]
    
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

    # Display results with better formatting
    st.subheader("Enrichment Results")
    
    # Create tooltips for each column
    tooltips = {
        'Indicator': 'The original IOC (IP, domain, or hash)',
        'Type': 'Automatically detected type of the indicator',
        'Threat Level': 'Overall threat assessment based on all sources',
        'OTX Pulse Count': 'Number of threat intelligence reports in AlienVault OTX',
        'OTX Malicious': 'Whether this IOC is flagged as malicious in OTX',
        'VT Malicious': 'Number of antivirus engines flagging as malicious',
        'VT Suspicious': 'Number of antivirus engines flagging as suspicious'
    }
    
    # Display the dataframe with custom styling
    st.dataframe(
        df_display,
        use_container_width=True,
        hide_index=True
    )
    
    # Download functionality
    csv = df_results.to_csv(index=False).encode('utf-8')
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
        8.8.8.8
        1.1.1.1
        ```
        
        **Domains:**
        ```
        google.com
        example.com
        ```
        
        **File Hashes (MD5/SHA256):**
        ```
        d41d8cd98f00b204e9800998ecf8427e
        9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08
        ```
        """)