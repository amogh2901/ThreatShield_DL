import sys
from pathlib import Path
sys.path.append(str(Path(__file__).resolve().parent))

import streamlit as st
from streamlit_autorefresh import st_autorefresh
import sqlite3
import pandas as pd
import plotly.express as px
import random
import time
import pickle
from threat_intelligence import get_threat_info
from response_engine import response_action
from attack_simulator import generate_attack
from threat_score import calculate_threat_score
from honeypot import check_honeypot
from detector import detect_attack
from logger import log_attack
from admin_config import ADMIN_PASSKEY

# ---------------- PAGE CONFIG ----------------
st.set_page_config(
    page_title="ThreatShield Security Platform",
    page_icon="🛡",
    layout="wide"
)

# ---------------- UI STYLE ----------------
st.markdown("""
<style>
body {background-color:#0A0F1C;}
h1 {color:#00E5FF;font-size:36px;}
.stButton>button {
background: linear-gradient(90deg,#00E5FF,#6366F1);
color:white;
border-radius:10px;
height:45px;
width:220px;
font-weight:bold;}
[data-testid="stMetric"] {
background:#111827;
padding:20px;
border-radius:12px;
border:1px solid #1F2937;}
</style>
""", unsafe_allow_html=True)

# ---------------- SIDEBAR ----------------
st.sidebar.title("🛡 ThreatShield")
page = st.sidebar.selectbox(
    "Navigation",
    ["Attack Detection", "Security Dashboard"]
)

# ------------------ Helper Functions ------------------

def load_attack_logs():
    try:
        conn = sqlite3.connect("database/logs.db")
        df = pd.read_sql_query("SELECT * FROM attack_logs", conn)
        conn.close()
        # Convert timestamp to datetime
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        return df
    except Exception as e:
        st.error(f"Database Error: {e}")
        return pd.DataFrame()

def get_filtered_logs(df, attack_type_filter, severity_filter, date_range, request_search):
    filtered_df = df.copy()

    # Filter by attack_type
    if attack_type_filter != "All":
        filtered_df = filtered_df[filtered_df["attack_type"] == attack_type_filter]

    # Filter by severity
    if severity_filter != "All":
        filtered_df = filtered_df[filtered_df["severity"] == severity_filter]

    # Filter by date range if provided
    if date_range is not None:
        start_date, end_date = date_range
        # Convert to pandas.Timestamp
        start_date = pd.Timestamp(start_date)
        end_date = pd.Timestamp(end_date) + pd.Timedelta(days=1)
        filtered_df = filtered_df[
            (filtered_df["timestamp"] >= start_date) &
            (filtered_df["timestamp"] < end_date)
        ]

    # Filter by request text
    if request_search:
        filtered_df = filtered_df[filtered_df["request"].str.contains(request_search, case=False, na=False)]

    return filtered_df

# Load model info for dynamic parameters
try:
    with open("model/model_info.pkl", "rb") as f:
        model_info = pickle.load(f)
        embedding_dim = model_info.get("embedding_dim", 128)
        num_classes = model_info.get("num_classes", 5)
        sequence_length = model_info.get("sequence_length", 200)
except:
    embedding_dim = 128
    num_classes = 5
    sequence_length = 200

# ------------------ Attack Detection Page (unchanged) ------------------
if page == "Attack Detection":
    st.title("ThreatShield DL - Web Attack Detection System")
    st.write("Analyze HTTP requests using Deep Learning to detect cyber attacks.")

    request = st.text_input("HTTP Request")

    if st.button("Analyze Request"):
        if request.strip() == "":
            st.warning("Please enter a request.")
            st.stop()

        if check_honeypot(request):
            st.error("🚨 Honeypot Triggered!")

        # Measure inference time
        start_time = time.perf_counter()
        result, confidence, probabilities = detect_attack(request)
        end_time = time.perf_counter()
        prediction_time_ms = (end_time - start_time) * 1000

        # Use confidence directly from model (no fake adjustment)
        confidence = round(confidence, 4)

        # Get threat info and calculate score
        info = get_threat_info(result) or {
            "severity": "MEDIUM",
            "description": "Unknown threat pattern detected.",
            "action": "Monitor request."
        }
        score = calculate_threat_score(info["severity"], confidence)

        # Log attack after severity is finalized
        log_attack(
            request=request,
            attack_type=result,
            confidence=confidence,
            severity=info["severity"],
            threat_score=score,
            prediction_time_ms=prediction_time_ms
        )

        # Update info based on result
        if result.lower() in ["normal", "legal"]:
            info["severity"] = "LOW"
            info["description"] = "Normal web request."
            info["action"] = "No action required."
        else:
            if info["severity"] == "CRITICAL":
                st.error("🚨 CRITICAL SECURITY THREAT")
            elif info["severity"] == "HIGH":
                st.warning("⚠ Malicious Activity")
            else:
                st.warning("⚠ Suspicious Request Detected")
        st.write("Severity:", info["severity"])
        st.write("Description:", info["description"])
        st.write("Recommended Action:", info["action"])

        # ---------------- Probability Chart ----------------
        if probabilities:
            # Convert probabilities to percentages
            prob_df = pd.DataFrame(
                probabilities.items(),
                columns=["Attack Type", "Probability"]
            )
            prob_df["Probability"] *= 100  # percentage

            fig = px.bar(
                prob_df,
                x="Attack Type",
                y="Probability",
                color="Attack Type",
                text_auto=".2f",
                title="Attack Prediction Probabilities"
            )
            st.plotly_chart(fig, use_container_width=True)

        # ---------------- Threat Intelligence ----------------
        info = get_threat_info(result)
        if info is None:
            info = {
                "severity": "MEDIUM",
                "description": "Unknown threat pattern detected.",
                "action": "Monitor request."
            }

        # ---------------- Deep Learning-Based Explanation ----------------
        if result.lower() in ["normal", "legal"]:
            explanation = "The Deep Learning model detected no malicious activity."
        elif result == "SQL Injection":
            explanation = "The Bi-Directional LSTM model detected SQL query manipulation patterns."
        elif result == "Cross Site Scripting":
            explanation = "The Bi-Directional LSTM model detected malicious JavaScript execution patterns."
        elif result == "Path Traversal":
            explanation = "The Bi-Directional LSTM model detected directory traversal attempts."
        elif result == "Phishing URL":
            explanation = "The Bi-Directional LSTM model detected characteristics of phishing URLs."
        else:
            explanation = "The request appears to be normal."

        st.markdown("## 🧠 AI Attack Explanation")
        st.info(explanation)

        # ---------------- SAFE / ATTACK DISPLAY ----------------
        if result.lower() in ["normal", "legal"]:
            st.success("✅ Safe Request")
            info["severity"] = "LOW"
            info["description"] = "Normal web request."
            info["action"] = "No action required."
        else:
            if info["severity"] == "CRITICAL":
                st.error("🚨 CRITICAL SECURITY THREAT")
            elif info["severity"] == "HIGH":
                st.warning("⚠ Malicious Activity")
            else:
                st.warning("⚠ Suspicious Request Detected")
        st.write("Severity:", info["severity"])
        st.write("Description:", info["description"])
        st.write("Recommended Action:", info["action"])

        # ---------------- Threat Score ----------------
        score = calculate_threat_score(info["severity"], confidence)
        score_percent = int(score * 100)
        st.subheader("Threat Score")
        st.progress(score)
        st.metric(
            "Risk Percentage",
            f"{score_percent}%"
        )

        # ---------------- Adaptive Response ----------------
        response = response_action(info["severity"])
        st.subheader("Adaptive Security Response")
        st.write("Status:", response["status"])
        st.write("Message:", response["message"])

        # ---------------- Model Details ----------------
        st.markdown(f"""
        ### 📚 Model Details
        - **Model:** Bi-Directional LSTM
        - **Embedding:** {embedding_dim} Dimensions
        - **Sequence Length:** {sequence_length}
        - **Framework:** TensorFlow 2.x
        - **Classes:** {num_classes}
        - **Prediction:** Softmax
        """)

# ------------------ Security Dashboard ------------------
if page == "Security Dashboard":
    st.title("ThreatShield Security Operations Center")
    st.markdown("### 🔐 Admin Access")
    passkey = st.text_input("Enter Admin Passkey", type="password")
    if passkey != ADMIN_PASSKEY:
        st.warning("Admin authentication required")
        st.stop()
    st.success("Admin Access Granted")
    st_autorefresh(interval=5000, key="refresh")

    # Load logs
    df = load_attack_logs()

    # ------------------ Filters ------------------
    st.sidebar.header("Filters")
    attack_type_options = ["All"]
    severity_options = ["All", "CRITICAL", "HIGH", "MEDIUM", "LOW"]
    date_min = None
    date_max = None

    if not df.empty:
        try:
            df['timestamp'] = pd.to_datetime(df['timestamp'])
            date_min = df['timestamp'].min().date()
            date_max = df['timestamp'].max().date()
        except Exception as e:
            st.error(f"Error processing timestamps: {e}")
    else:
        date_min = None
        date_max = None

    # Add date range input widget
    if date_min is not None and date_max is not None:
        selected_dates = st.sidebar.date_input(
            "Select Date Range",
            value=[date_min, date_max],
            min_value=date_min,
            max_value=date_max
        )
        if isinstance(selected_dates, (tuple, list)) and len(selected_dates) == 2:
            start_date, end_date = selected_dates[0], selected_dates[1]
            date_range = (pd.to_datetime(start_date), pd.to_datetime(end_date))
        elif isinstance(selected_dates, (tuple, list)) and len(selected_dates) == 1:
            start_date = selected_dates[0]
            date_range = (pd.to_datetime(start_date), pd.to_datetime(start_date))
        else:
            date_range = None
    else:
        date_range = None

    attack_type_filter = st.sidebar.selectbox(
        "Attack Type",
        options=attack_type_options + (sorted(df["attack_type"].unique().tolist()) if not df.empty else [])
    )
    severity_filter = st.sidebar.selectbox(
        "Severity",
        options=severity_options
    )
    request_search = st.sidebar.text_input("Search Request")

    # Filter logs with date_range
    filtered_df = get_filtered_logs(df, attack_type_filter, severity_filter, date_range, request_search)

    # ------------------ Metrics ------------------
    total_requests = len(df)
    normal_labels = ["Normal", "LEGAL"]
    malicious_requests = len(df[~df["attack_type"].isin(normal_labels)]) if not df.empty else 0
    safe_requests = len(df[df["attack_type"].isin(normal_labels)]) if not df.empty else 0

    # Calculate metrics safely
    confidence_avg = df["confidence"].mean() * 100 if "confidence" in df.columns and not df["confidence"].empty else 0
    threat_score_avg = df["threat_score"].mean() if "threat_score" in df.columns and not df["threat_score"].empty else 0
    prediction_time_avg = df["prediction_time_ms"].mean() if "prediction_time_ms" in df.columns and not df["prediction_time_ms"].empty else 0
    critical_count = len(df[df["severity"] == "CRITICAL"]) if "severity" in df.columns else 0
    high_count = len(df[df["severity"] == "HIGH"]) if "severity" in df.columns else 0
    medium_count = len(df[df["severity"] == "MEDIUM"]) if "severity" in df.columns else 0
    low_count = len(df[df["severity"] == "LOW"]) if "severity" in df.columns else 0

    # Display metrics in cleaner layout
    col1, col2, col3, col4 = st.columns([1, 1, 1, 1])
    col1.metric("Total Requests", total_requests)
    col2.metric("Safe Requests", safe_requests)
    col3.metric("Malicious Requests", malicious_requests)
    col4.metric("Critical", critical_count)

    col5, col6, col7, col8 = st.columns([1, 1, 1, 1])
    col5.metric("Confidence", f"{confidence_avg:.2f}%")
    col6.metric("Threat Score", f"{threat_score_avg:.2f}")
    col7.metric("Prediction Time", f"{prediction_time_avg:.2f} ms")
    col8.metric("High Severity", high_count)

    col9, col10 = st.columns([1, 1])
    col9.metric("Medium", medium_count)
    col10.metric("Low", low_count)

    # ------------------ Charts ------------------
    # Attack Type Pie Chart
    attack_counts = pd.Series()
    if not df.empty and "attack_type" in df.columns:
        attack_counts = df["attack_type"].value_counts()
    if not attack_counts.empty:
        fig_attack_type = px.pie(
            attack_counts,
            values=attack_counts.values,
            labels=attack_counts.index,
            title="Attack Type Distribution"
        )
        st.plotly_chart(fig_attack_type, use_container_width=True)
    else:
        st.info("No attack data available.")

    # Severity Pie Chart
    severity_counts = pd.Series()
    if not df.empty and "severity" in df.columns:
        severity_counts = df["severity"].value_counts()
    if not severity_counts.empty:
        fig_severity = px.pie(
            severity_counts,
            values=severity_counts.values,
            labels=severity_counts.index,
            title="Severity Distribution"
        )
        st.plotly_chart(fig_severity, use_container_width=True)
    else:
        st.info("No severity data available.")

    # Attacks over time line chart
    if not df.empty:
        try:
            df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
            df = df.dropna(subset=["timestamp"])
            df['date'] = pd.DatetimeIndex(df['timestamp']).date
            attacks_over_time = df.groupby('date').size().reset_index(name='counts')
            fig_time = px.line(
                attacks_over_time,
                x='date',
                y='counts',
                title='Number of Attacks Over Time'
            )
            st.plotly_chart(fig_time, use_container_width=True)
        except:
            pass

    # Confidence histogram
    if not df.empty and "confidence" in df.columns:
        fig_confidence = px.histogram(
            df,
            x='confidence',
            nbins=20,
            title='Confidence Scores Distribution'
        )
        st.plotly_chart(fig_confidence, use_container_width=True)

    # Prediction time histogram
    if not df.empty and "prediction_time_ms" in df.columns:
        fig_pred_time = px.histogram(
            df,
            x='prediction_time_ms',
            nbins=20,
            title='Prediction Time Distribution (ms)'
        )
        st.plotly_chart(fig_pred_time, use_container_width=True)

    # Threat score by attack type bar chart
    if not df.empty and "attack_type" in df.columns and "threat_score" in df.columns:
        threat_score_by_type = df.groupby('attack_type')['threat_score'].mean().reset_index()
        fig_threat = px.bar(
            threat_score_by_type,
            x='attack_type',
            y='threat_score',
            title='Average Threat Score by Attack Type'
        )
        st.plotly_chart(fig_threat, use_container_width=True)

    # ---------------- Attack Logs Table ----------------
    st.markdown("### Attack Logs")
    display_cols = ['timestamp', 'request', 'attack_type', 'confidence', 'severity', 'threat_score', 'prediction_time_ms']
    # Ensure columns exist
    for col in display_cols:
        if col not in filtered_df.columns:
            filtered_df[col] = ''
    st.dataframe(
        filtered_df[display_cols].sort_values(by='timestamp', ascending=False),
        use_container_width=True
    )

    # ---------------- Export Logs ----------------
    csv = filtered_df.to_csv(index=False).encode('utf-8')
    st.download_button(
        label="Download Attack Logs as CSV",
        data=csv,
        file_name="attack_logs.csv",
        mime="text/csv"
    )

    # ---------------- Global Attack Map ----------------
    st.markdown("### 🌍 Global Attack Map")
    countries = [
        ("USA", 37.0902, -95.7129),
        ("Russia", 61.5240, 105.3188),
        ("China", 35.8617, 104.1954),
        ("India", 20.5937, 78.9629),
        ("Germany", 51.1657, 10.4515),
        ("Brazil", -14.2350, -51.9253),
        ("UK", 55.3781, -3.4360),
        ("Canada", 56.1304, -106.3468)
    ]
    attack_map = []
    for index, row in filtered_df.iterrows():
        if row["attack_type"] not in ["Normal", "LEGAL"]:
            country = random.choice(countries)
            attack_map.append({
                "country": country[0],
                "lat": country[1],
                "lon": country[2],
                "attack": row["attack_type"]
            })
    if attack_map:
        map_df = pd.DataFrame(attack_map)
        fig = px.scatter_geo(
            map_df,
            lat="lat",
            lon="lon",
            color="attack",
            hover_name="country",
            projection="natural earth"
        )
        fig.update_traces(marker=dict(size=14, opacity=0.9))
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("No malicious attacks recorded yet.")

        st.info("No malicious attacks recorded yet.")