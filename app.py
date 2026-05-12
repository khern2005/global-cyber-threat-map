import streamlit as st
import pandas as pd
import plotly.graph_objects as go
import plotly.express as px
import requests
from io import StringIO
from datetime import datetime
from streamlit_autorefresh import st_autorefresh

st.set_page_config(
    page_title="Global Cyber Threat Map",
    page_icon="🌍",
    layout="wide"
)

# st.markdown(
#     """
#     <style>

#     /* Main app background */
#     .stApp {
#         background-color: #0e1117;
#         color: #f5f5f5;
#     }

#     /* Main content */
#     .main {
#         background-color: #0e1117;
#         color: #f5f5f5;
#     }

#     /* All text */
#     html, body, [class*="css"] {
#         color: #f5f5f5 !important;
#     }

#     /* Headers */
#     h1, h2, h3, h4 {
#         color: #f5f5f5 !important;
#     }

#     /* Metric cards */
#     div[data-testid="metric-container"] {
#         background-color: #161b22;
#         border: 1px solid #30363d;
#         padding: 15px;
#         border-radius: 12px;
#     }

#     /* Metric text */
#     div[data-testid="metric-container"] * {
#         color: #f5f5f5 !important;
#     }

#     /* Sidebar */
#     section[data-testid="stSidebar"] {
#         background-color: #111827;
#     }

#     section[data-testid="stSidebar"] * {
#         color: #f5f5f5 !important;
#     }

#     /* Threat cards */
#     .threat-card {
#         background-color: #161b22;
#         padding: 14px;
#         border-radius: 12px;
#         border-left: 5px solid #ff4b4b;
#         margin-bottom: 10px;
#         color: #f5f5f5 !important;
#     }

#     /* Muted text */
#     .small-muted {
#         color: #9ca3af !important;
#         font-size: 14px;
#     }

#     /* Tables */
#     .stDataFrame {
#         background-color: #161b22;
#     }

#     </style>
#     """,
#     unsafe_allow_html=True
# )

st.markdown("# 🌍 Global Cyber Threat Intelligence Dashboard")
st.markdown(
    "<p class='small-muted'>Real public threat intelligence mapped by geolocation, severity, and source.</p>",
    unsafe_allow_html=True
)

refresh_count = st_autorefresh(
    interval=60 * 1000,
    key="threat_map_refresh"
)

st.caption(f"Dashboard refreshed: {datetime.now().strftime('%Y-%m-%d %I:%M:%S %p')}")
st.caption("Threat feeds are cached to avoid overloading public sources.")

FEODO_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.csv"
SPAMHAUS_DROP_URL = "https://www.spamhaus.org/drop/drop.txt"


@st.cache_data(ttl=600)
def load_feodo_data():
    response = requests.get(FEODO_URL, timeout=10)
    response.raise_for_status()

    lines = response.text.splitlines()
    csv_lines = [line for line in lines if line and not line.startswith("#")]

    df = pd.read_csv(
        StringIO("\n".join(csv_lines)),
        skiprows=1,
        header=None,
        names=["first_seen", "ip_address", "port", "status", "last_seen", "malware_family"]
    )

    df["source"] = "Feodo Tracker"
    df["network"] = "N/A"
    df["reason"] = "Botnet C2 indicator"

    return df


@st.cache_data(ttl=3600)
def load_spamhaus_drop_data():
    response = requests.get(SPAMHAUS_DROP_URL, timeout=10)
    response.raise_for_status()

    rows = []

    for line in response.text.splitlines():
        line = line.strip()

        if not line or line.startswith(";"):
            continue

        parts = line.split(";")
        network = parts[0].strip()
        reason = parts[1].strip() if len(parts) > 1 else "Spamhaus DROP"
        anchor_ip = network.split("/")[0]

        rows.append({
            "first_seen": "N/A",
            "ip_address": anchor_ip,
            "port": "N/A",
            "status": "listed",
            "last_seen": "N/A",
            "malware_family": "Spamhaus DROP",
            "source": "Spamhaus DROP",
            "network": network,
            "reason": reason
        })

    return pd.DataFrame(rows)


@st.cache_data(ttl=3600)
def geolocate_ip(ip_address):
    ip_address = str(ip_address).strip()

    url = f"http://ip-api.com/json/{ip_address}?fields=status,message,country,countryCode,lat,lon,isp,org,as"

    response = requests.get(url, timeout=10)
    response.raise_for_status()

    data = response.json()

    if data.get("status") != "success":
        return None

    return {
        "ip_address": ip_address,
        "country": data.get("country"),
        "country_code": data.get("countryCode"),
        "lat": data.get("lat"),
        "lon": data.get("lon"),
        "isp": data.get("isp"),
        "org": data.get("org"),
        "asn": data.get("as")
    }


def assign_severity(row):
    malware = str(row["malware_family"]).lower()
    status = str(row["status"]).lower()
    source = str(row["source"]).lower()

    if status == "online":
        return "Critical"
    elif "qakbot" in malware or "emotet" in malware:
        return "High"
    elif "spamhaus" in source:
        return "Medium"
    else:
        return "Low"


with st.sidebar:
    st.header("Threat Filters")

    if st.button("Refresh Now"):
        st.cache_data.clear()
        st.rerun()


try:
    feodo_df = load_feodo_data()
    spamhaus_df = load_spamhaus_drop_data().head(25)

    df = pd.concat([feodo_df, spamhaus_df], ignore_index=True)

    st.subheader("Threat Feed Sources")

    source_counts = df["source"].value_counts()

    source_col1, source_col2 = st.columns(2)

    source_col1.metric("Feodo Tracker", int(source_counts.get("Feodo Tracker", 0)))
    source_col2.metric("Spamhaus DROP", int(source_counts.get("Spamhaus DROP", 0)))

    st.subheader("Threat Summary")

    col1, col2, col3 = st.columns(3)

    col1.metric("Total Indicators", len(df))
    col2.metric("Unique Ports", df["port"].astype(str).nunique())
    col3.metric("Data Sources", df["source"].nunique())

    st.subheader("Real Geolocated Threat Map")
    st.caption(f"Last updated: {datetime.now().strftime('%Y-%m-%d %I:%M:%S %p')}")

    sample_df = df.head(30).copy()

    map_rows = []

    for _, row in sample_df.iterrows():
        ip = str(row["ip_address"]).strip()
        geo_data = geolocate_ip(ip)

        if geo_data:
            combined_row = row.to_dict()
            combined_row.update(geo_data)
            map_rows.append(combined_row)

    map_df = pd.DataFrame(map_rows)

    if map_df.empty:
        st.warning("No geolocated IPs available to plot right now.")
        st.stop()

    map_df["count"] = 10
    map_df["port"] = map_df["port"].astype(str)
    map_df["severity"] = map_df.apply(assign_severity, axis=1)

    selected_source = st.sidebar.multiselect(
        "Data Source",
        options=sorted(map_df["source"].dropna().unique()),
        default=[]
    )

    selected_status = st.sidebar.multiselect(
        "Status",
        options=sorted(map_df["status"].dropna().unique()),
        default=[]
    )

    selected_malware = st.sidebar.multiselect(
        "Malware Family",
        options=sorted(map_df["malware_family"].dropna().unique()),
        default=[]
    )

    port_options = sorted(map_df["port"].dropna().astype(str).unique())

    selected_ports = st.sidebar.multiselect(
        "Ports",
        options=port_options,
        default=[]
    )

    selected_severity = st.sidebar.multiselect(
        "Severity",
        options=["Critical", "High", "Medium", "Low"],
        default=[]
    )

    filtered_df = map_df.copy()
    filtered_df["port"] = filtered_df["port"].astype(str)

    if selected_source:
        filtered_df = filtered_df[filtered_df["source"].isin(selected_source)]

    if selected_status:
        filtered_df = filtered_df[filtered_df["status"].isin(selected_status)]

    if selected_malware:
        filtered_df = filtered_df[filtered_df["malware_family"].isin(selected_malware)]

    if selected_ports:
        filtered_df = filtered_df[filtered_df["port"].isin(selected_ports)]

    if selected_severity:
        filtered_df = filtered_df[filtered_df["severity"].isin(selected_severity)]

    col1, col2, col3, col4, col5 = st.columns(5)

    col1.metric("Visible Threats", len(filtered_df))
    col2.metric("Countries", filtered_df["country"].nunique())
    col3.metric("Malware Families", filtered_df["malware_family"].nunique())
    col4.metric("Ports", filtered_df["port"].nunique())
    col5.metric("Critical", len(filtered_df[filtered_df["severity"] == "Critical"]))

    target_country = "United States"
    target_lat = 37.0902
    target_lon = -95.7129

    severity_colors = {
        "Critical": "red",
        "High": "orange",
        "Medium": "yellow",
        "Low": "lightblue"
    }

    fig = go.Figure()

    for _, row in filtered_df.iterrows():
        fig.add_trace(
            go.Scattergeo(
                lon=[row["lon"], target_lon],
                lat=[row["lat"], target_lat],
                mode="lines",
                line=dict(
                    width=2,
                    color=severity_colors.get(row["severity"], "gray")
                ),
                opacity=0.5,
                hoverinfo="text",
                text=f"{row['ip_address']} → {target_country}<br>{row['source']}<br>{row['malware_family']}<br>Severity: {row['severity']}",
                showlegend=False
            )
        )

    fig.add_trace(
        go.Scattergeo(
            lon=filtered_df["lon"],
            lat=filtered_df["lat"],
            mode="markers",
            marker=dict(
                size=10,
                opacity=0.85,
                color=filtered_df["severity"].map(severity_colors)
            ),
            text=filtered_df.apply(
                lambda row: f"""
                <b>Source IP:</b> {row['ip_address']}<br>
                <b>Country:</b> {row['country']}<br>
                <b>Data Source:</b> {row['source']}<br>
                <b>Malware/Category:</b> {row['malware_family']}<br>
                <b>Severity:</b> {row['severity']}<br>
                <b>Port:</b> {row['port']}<br>
                <b>Status:</b> {row['status']}<br>
                <b>ISP:</b> {row['isp']}<br>
                <b>Org:</b> {row['org']}<br>
                <b>ASN:</b> {row['asn']}<br>
                <b>Network:</b> {row['network']}<br>
                <b>Reason:</b> {row['reason']}
                """,
                axis=1
            ),
            hoverinfo="text",
            name="Threat Source"
        )
    )

    fig.add_trace(
        go.Scattergeo(
            lon=[target_lon],
            lat=[target_lat],
            mode="markers",
            marker=dict(
                size=22,
                symbol="star",
                color="blue",
                line=dict(width=2, color="black")
            ),
            text=[f"<b>Target:</b> {target_country}"],
            hoverinfo="text",
            name="Simulated Target"
        )
    )

    fig.update_layout(
        title="Global Threat Activity → Simulated U.S. Target",
        height=650,
        margin=dict(l=0, r=0, t=50, b=0),
        geo=dict(
            projection_type="natural earth",
            showland=True,
            landcolor="#1f2937",
            showcountries=True,
            countrycolor="#4b5563",
            showocean=True,
            oceancolor="#020617",
            showlakes=True,
            lakecolor="#020617",
            bgcolor="#0e1117",
            fitbounds="locations"
        ),
        paper_bgcolor="#0e1117",
        plot_bgcolor="#0e1117",
        font=dict(color="#f5f5f5")
    )

    st.plotly_chart(fig, use_container_width=True)

    st.subheader("Threat Intelligence Breakdown")

    chart_col1, chart_col2 = st.columns(2)

    with chart_col1:
        country_counts = filtered_df["country"].value_counts().reset_index()
        country_counts.columns = ["Country", "Count"]

        fig_country = px.bar(
            country_counts.head(10),
            x="Country",
            y="Count",
            title="Top Threat Source Countries"
        )

        fig_country.update_layout(
            paper_bgcolor="#0e1117",
            plot_bgcolor="#161b22",
            font=dict(color="#f5f5f5")
        )

        st.plotly_chart(fig_country, use_container_width=True)

    with chart_col2:
        malware_counts = filtered_df["malware_family"].value_counts().reset_index()
        malware_counts.columns = ["Malware/Category", "Count"]

        fig_malware = px.bar(
            malware_counts.head(10),
            x="Malware/Category",
            y="Count",
            title="Top Malware Families / Categories"
        )

        fig_malware.update_layout(
            paper_bgcolor="#0e1117",
            plot_bgcolor="#161b22",
            font=dict(color="#f5f5f5")
        )

        st.plotly_chart(fig_malware, use_container_width=True)

    st.subheader("Live Threat Activity Feed")

    recent_events = filtered_df.head(10)

    for _, row in recent_events.iterrows():
        st.markdown(
            f"""
            <div class="threat-card">
                <b>🚨 {row['severity']} Threat</b> from <b>{row['country']}</b><br>
                <span class="small-muted">
                IP: {row['ip_address']} | Category: {row['malware_family']} | Port: {row['port']} | Source: {row['source']}
                </span>
            </div>
            """,
            unsafe_allow_html=True
        )

    st.subheader("Recent Threat Feed")

    st.dataframe(
        filtered_df[[
            "severity",
            "source",
            "ip_address",
            "country",
            "port",
            "status",
            "malware_family",
            "isp",
            "org",
            "asn",
            "network",
            "reason"
        ]],
        use_container_width=True
    )

    st.markdown("---")
    st.markdown(
        "<p class='small-muted'>Built with Python, Streamlit, Plotly, Feodo Tracker, Spamhaus DROP, and IP geolocation.</p>",
        unsafe_allow_html=True
    )

except Exception as e:
    st.error("Could not load threat intelligence feed.")
    st.exception(e)