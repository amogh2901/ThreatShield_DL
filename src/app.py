import sys
from pathlib import Path

# Set project root path
PROJECT_ROOT = Path(__file__).resolve().parent.parent

# Ensure database directory exists
DB_DIR = PROJECT_ROOT / "database"
DB_DIR.mkdir(parents=True, exist_ok=True)

# Path to logs database
DB_PATH = DB_DIR / "logs.db"

# Append to sys path for module imports
sys.path.append(str(PROJECT_ROOT))
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
from threat_score import calculate_threat_score
from honeypot import check_honeypot
from detector import detect_attack
from explainability.explanation_engine import ExplanationEngine
from logger import log_attack
from admin_config import ADMIN_PASSKEY

# Load model info path
MODEL_INFO_PATH = PROJECT_ROOT / "model" / "model_info.pkl"

# Initialize explainability engine
explainer = ExplanationEngine()

# ---------------- PAGE CONFIG ----------------
st.set_page_config(
    page_title="DeepWAF-XAI Security Platform",
    page_icon="🛡",
    layout="wide"
)

# ---------------- CYBER SECURITY UI ----------------
st.markdown("""
<style>

/* Main Background */
.stApp{
    background:#0B1220;
    color:white;
}

/* Sidebar */
section[data-testid="stSidebar"]{
    background:#111827;
    border-right:1px solid #1F2937;
}

/* Titles */
h1{
    color:#00E5FF;
    font-size:40px;
    font-weight:700;
}

h2,h3{
    color:#60A5FA;
}

/* Buttons */
.stButton>button{

    background:linear-gradient(90deg,#00BFFF,#2563EB);
    color:white;

    border:none;

    border-radius:12px;

    font-weight:600;

    transition:.35s;

    animation:fadeInUp .6s ease;

}

.stButton>button:hover{

    transform:translateY(-3px) scale(1.02);

    box-shadow:0 0 18px rgba(0,191,255,.35);

}

/* Text Input */
.stTextInput input{
    background:#1A2332;
    color:white;
    border-radius:10px;
    border:1px solid #334155;
}

/* Metrics */
[data-testid="stMetric"]{

    background:linear-gradient(180deg,#111827,#182234);

    border:1px solid #26354d;

    border-radius:18px;

    padding:18px;

    transition:.35s;

    animation:fadeInUp .6s ease;

}

[data-testid="stMetric"]:hover{

    transform:translateY(-6px);

    border:1px solid #00BFFF;

    box-shadow:0 0 18px rgba(0,191,255,.35);

}

[data-testid="stAlert"]{

    animation:fadeInUp .5s ease;

}

[data-testid="stMetric"]:hover{
    transform:translateY(-5px);
    border:1px solid #00BFFF;
    box-shadow:0 0 22px rgba(0,191,255,.25);
}

/* Expanders */
.streamlit-expanderHeader{
    background:#1A2332;
    border-radius:8px;
}

/* Dataframe */
[data-testid="stDataFrame"]{
    border-radius:10px;
}

/* Progress Bar */
.stProgress > div > div > div > div{

    background:#00E676;

    animation:pulse 1.8s infinite;

}

/* ================= Analyzer Card ================= */

.analyzer-card{
    background:#101827;
    border:1px solid #24364F;
    border-radius:18px;
    padding:25px;
    margin-top:15px;
    margin-bottom:20px;
    box-shadow:0 0 18px rgba(0,191,255,.08);
}

.analyzer-title{
    font-size:28px;
    font-weight:700;
    color:white;
    margin-bottom:8px;
}
.analyzer-card{
    margin-top:20px;
    margin-bottom:30px;
}
.analyzer-subtitle{
    color:#AAB8D3;
    font-size:15px;
    margin-bottom:20px;
}
.metric-card{
    background:linear-gradient(180deg,#131c2c,#1a2437);
    border:1px solid #26354d;
    border-radius:18px;
    padding:18px;
    transition:.3s;
    min-height:120px;
}

.metric-card:hover{
    border:1px solid #00BFFF;
    box-shadow:0 0 20px rgba(0,191,255,.20);
    transform:translateY(-5px);
}

.metric-title{
    color:#A7B3C7;
    font-size:15px;
    margin-top:10px;
}

.metric-value{
    color:white;
    font-size:34px;
    font-weight:700;
}

.metric-icon{
    font-size:30px;
}

/* ==============================
   Animations
==============================*/

@keyframes fadeInUp{
    from{
        opacity:0;
        transform:translateY(25px);
    }
    to{
        opacity:1;
        transform:translateY(0);
    }
}

@keyframes fadeIn{
    from{
        opacity:0;
    }
    to{
        opacity:1;
    }
}

@keyframes glow{
    0%{
        box-shadow:0 0 6px rgba(0,191,255,.15);
    }

    50%{
        box-shadow:0 0 22px rgba(0,191,255,.45);
    }

    100%{
        box-shadow:0 0 6px rgba(0,191,255,.15);
    }
}

@keyframes pulse{

    0%{
        transform:scale(1);
    }

    50%{
        transform:scale(1.04);
    }

    100%{
        transform:scale(1);
    }

}
</style>
""", unsafe_allow_html=True)

# ---------------- Navigation ----------------
st.sidebar.image(
    "https://img.icons8.com/fluency/96/shield.png",
    width=70
)

st.sidebar.title("DeepWAF-XAI")

st.sidebar.caption(
    "Explainable Deep Learning Framework"
)

st.sidebar.markdown("---")

page = st.sidebar.radio(
    "Navigation",
    [
        "🛡 Attack Detection",
        "📊 Security Dashboard"
    ]
)

# ---------------- Helper functions ----------------

def create_attack_logs_table():
    """Create logs table if it doesn't exist."""
    try:
        with sqlite3.connect(DB_PATH) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS attack_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT,
                    request TEXT,
                    attack_type TEXT,
                    confidence REAL,
                    severity TEXT,
                    threat_score REAL,
                    prediction_time_ms REAL
                )
            """)
    except Exception as e:
        st.error(f"Database setup error: {e}")

def load_model_info():
    try:
        with open(MODEL_INFO_PATH, "rb") as f:
            return pickle.load(f)
    except Exception:
        return {
            "embedding_dim": 128,
            "num_classes": 5,
            "sequence_length": 200
        }

def get_db_connection():
    try:
        return sqlite3.connect(DB_PATH)
    except Exception as e:
        st.error(f"Database connection error: {e}")
        return None

def load_attack_logs() -> pd.DataFrame:
    try:
        conn = get_db_connection()
        if conn is None:
            return pd.DataFrame()
        df = pd.read_sql_query("SELECT * FROM attack_logs", conn)
        conn.close()
        if not df.empty:
            df['timestamp'] = pd.to_datetime(df['timestamp'])
        return df
    except Exception as e:
        st.error(f"Error loading logs: {e}")
        return pd.DataFrame()

def get_live_stats():
    df = load_attack_logs()

    if df.empty:
        return {
            "total": 0,
            "safe": 0,
            "malicious": 0,
            "critical": 0,
            "avg_score": 0
        }

    normal = ["Normal", "LEGAL"]

    total = len(df)
    safe = len(df[df["attack_type"].isin(normal)])
    malicious = len(df[~df["attack_type"].isin(normal)])
    critical = len(df[df["severity"] == "CRITICAL"])

    avg_score = (
        df["threat_score"].mean()
        if "threat_score" in df.columns
        else 0
    )

    return {
        "total": total,
        "safe": safe,
        "malicious": malicious,
        "critical": critical,
        "avg_score": avg_score
    }

def get_filtered_logs(df, attack_type, severity, date_range, request_search):
    filtered = df.copy()
    if attack_type != "All":
        filtered = filtered[filtered["attack_type"] == attack_type]
    if severity != "All":
        filtered = filtered[filtered["severity"] == severity]
    if date_range:
        start_dt, end_dt = date_range
        filtered = filtered[
            (filtered["timestamp"] >= start_dt) &
            (filtered["timestamp"] < end_dt + pd.Timedelta(days=1))
        ]
    if request_search:
        filtered = filtered[filtered["request"].str.contains(request_search, case=False, na=False)]
    return filtered

# Create logs table once
create_attack_logs_table()

# ---------------- Attack Detection Page ----------------
if page == "🛡 Attack Detection":
    st.title("🛡 DeepWAF-XAI")

    st.caption(
        "An Explainable Deep Learning Framework for Real-Time Web Attack Detection and Intelligent Threat Mitigation"
    )

    st.markdown("""
    <div style="
    background:#133b2f;
    border:1px solid #1ea96c;
    padding:16px;
    border-radius:12px;
    font-size:18px;
    animation:glow 2s infinite;
    ">

    🟢 <b>AI Engine Active</b> |
    Character-Level Stacked BiLSTM Loaded

    </div>

    <br>
    """, unsafe_allow_html=True)
    st.markdown("""
    <div class="analyzer-card">

    <div class="analyzer-title">
    🎯 Analyze HTTP Request / URL / Payload
    </div>

    <div class="analyzer-subtitle">
    Paste your HTTP request, URL or payload below for analysis.
    </div>
    """, unsafe_allow_html=True)
# =========================
# Request Input Section
# =========================


    left, right = st.columns([7,3], gap="large")

# ================= LEFT (70%)
    with left:

        if "request_input" not in st.session_state:
            st.session_state.request_input = ""

        request_input = st.text_area(
            "Paste HTTP Request / URL / Payload",
            key="request_input",
            height=250,
            placeholder="Paste your HTTP request, URL or payload here..."
        )

        st.caption(f"Characters : {len(request_input)} / 5000")

        analyze = st.button(
            "🔍 Analyze Request",
            use_container_width=True
        )


# ================= RIGHT (30%)
    with right:

        with st.popover("❓ Help / Examples", use_container_width=True):

            st.markdown("### Example Inputs")

            st.code(
                "<script>alert('XSS')</script>",
                language="html"
            )

            st.code(
                "SELECT * FROM users WHERE username='admin'--",
                language="sql"
            )

            st.code(
                "../../../etc/passwd",
                language="text"
            )

            st.code(
                "https://paypa1-login-security.com",
                language="text"
            )

            st.info("""
### 🔒 What happens next?

• Attack Type Prediction

• Confidence Score

• Explainable AI

• Threat Intelligence

• Recommended Action
""")
    st.markdown("</div>", unsafe_allow_html=True)


    if analyze:
        if not request_input.strip():
            st.warning("Please enter a request.")
        elif check_honeypot(request_input):
            st.error("🚨 Honeypot Triggered!")
        else:
            progress = st.progress(0)
            status = st.empty()

            steps = [
                "🔍 Parsing HTTP Request...",
                "🧠 Running Deep Learning Model...",
                "📊 Calculating Confidence...",
                "🛡 Mapping Threat Intelligence...",
                "⚡ Generating Explainable AI..."
            ]

            for i, step in enumerate(steps):
                status.info(step)
                with st.spinner("Running DeepWAF-XAI..."):
                    attack_type, confidence, probabilities = detect_attack(request_input)
                progress.progress((i + 1) * 20)
                time.sleep(0.35)

            start_time = time.perf_counter()

            attack_type, confidence, probabilities = detect_attack(request_input)

            progress.progress(100)
            status.success("✅ Analysis Completed")
            time.sleep(0.5)

            progress.empty()
            status.empty()
            explanation_result = explainer.explain(payload=request_input, prediction=attack_type, confidence=confidence)
            end_time = time.perf_counter()
            prediction_time_ms = (end_time - start_time) * 1000

            model_info = load_model_info()

            embedding_dim = model_info.get("embedding_dim", 128)
            sequence_length = model_info.get(
                "sequence_length",
                model_info.get("max_sequence_length", 200)
            )
            classes = model_info.get("classes", [])
            num_classes = len(classes) if classes else 5

            info = get_threat_info(attack_type) or {
                "severity": "MEDIUM",
                "description": "Unknown threat pattern detected.",
                "action": "Monitor request.",
                "mitre": "",
                "cvss": "",
                "recommendation": ""
            }

            # Calculate threat score once
            threat_score = calculate_threat_score(info["severity"], confidence)

            # Log attack
            log_attack(
                request=request_input,
                attack_type=attack_type,
                confidence=confidence,
                severity=info["severity"],
                threat_score=threat_score,
                prediction_time_ms=prediction_time_ms
            )

            # Show detection result
            if attack_type.lower() in ["normal", "legal"]:
                info["severity"] = "LOW"
                info["description"] = "Normal web request."
                info["action"] = "No action required."
                placeholder = st.empty()

                text = "✅ Safe Request"

                output = ""

                for c in text:
                    output += c
                    placeholder.success(output)
                    time.sleep(0.03)
            else:
                if info["severity"] == "CRITICAL":
                    st.error("🚨 CRITICAL SECURITY THREAT")
                elif info["severity"] == "HIGH":
                    st.warning("⚠ Malicious Activity")
                else:
                    st.warning("⚠ Suspicious Request Detected")

            # Threat Intelligence
            st.subheader("🛡 Threat Intelligence")
            st.write("**Severity:**", info.get("severity", "N/A"))
            st.write("**Description:**", info.get("description", "N/A"))
            st.write("**Recommended Action:**", info.get("action", "N/A"))
            st.write("**MITRE ATT&CK:**", info.get("mitre", "N/A"))
            st.write("**CVSS Score:**", info.get("cvss", "N/A"))
            st.write("**Security Recommendation:**", info.get("recommendation", "N/A"))

            # Probability chart
            if probabilities:
                df_probs = pd.DataFrame(
                    probabilities.items(),
                    columns=["Attack Type", "Probability"]
                )
                df_probs["Probability"] *= 100
                df_probs = df_probs.sort_values("Probability", ascending=False)
                fig = px.bar(
                    df_probs,
                    x="Attack Type",
                    y="Probability",
                    color="Attack Type",
                    text_auto=".2f",
                    title="Attack Prediction Probabilities"
                )
                with st.spinner("Generating attack probability..."):
                    time.sleep(0.4)
                st.plotly_chart(fig)

            # Explainability
            st.markdown("## 🧠 Explainable AI")
            with st.expander("View AI Decision Explanation", expanded=True):
                st.success(f"Prediction : {explanation_result['prediction']}")
                st.metric("Model Confidence", f"{explanation_result['confidence']:.2f}%")
                st.write("### Decision Reasons")
                for reason in explanation_result["explanation"]:
                    st.markdown(f"✔ {reason}")
                st.write("### Recommended Action")
                st.warning(explanation_result["recommended_action"])

            # Threat Score
            st.subheader("Threat Score")
            bar = st.progress(0)

            for i in range(int(threat_score * 100) + 1):
                bar.progress(i)
                time.sleep(0.004)

            if threat_score >= 0.90:
                st.error("🚨 CRITICAL RISK")

            elif threat_score >= 0.70:
                st.warning("⚠ HIGH RISK")

            elif threat_score >= 0.40:
                st.info("🟠 MEDIUM RISK")

            else:
                st.success("🟢 LOW RISK")


            # Adaptive Response
            response = response_action(info["severity"])
            # Safeguard keys with get()
            st.subheader("🛡 Adaptive Security Response")
            st.write("**Status:**", response.get("status", "N/A"))
            st.write("**Message:**", response.get("message", "N/A"))
            st.write("Firewall:", response.get("firewall", "N/A"))
            st.write("Admin Alert:", response.get("admin_alert", "N/A"))
            st.write("Log Status:", response.get("log_status", "N/A"))
            st.write("Recommended Action:", response.get("recommended_action", "N/A"))

            # Model details (already loaded above)
            st.markdown(f"""
            ### 📚 Model Details
            - **Model:** Bi-Directional LSTM
            - **Embedding:** {embedding_dim} Dimensions
            - **Sequence Length:** {sequence_length}
            - **Framework:** TensorFlow 2.x
            - **Classes:** {num_classes}
            - **Prediction:** Softmax
            """)
        
    stats = get_live_stats()

    st.markdown("<br>", unsafe_allow_html=True)

    cards = [
        ("📨","Total Requests",stats["total"]),
        ("✅","Safe Requests",stats["safe"]),
        ("🚨","Malicious",stats["malicious"]),
        ("☠","Critical",stats["critical"]),
        ("🎯","Avg Score",f"{stats['avg_score']:.2f}")
    ]

    cols = st.columns(5)

    for col,(icon,title,value) in zip(cols,cards):
        with col:
            st.markdown(f"""
            <div class="metric-card">
                <div class="metric-icon">{icon}</div>
                <div class="metric-title">{title}</div>
                <div class="metric-value">{value}</div>
            </div>
            """,unsafe_allow_html=True)
        
    st.markdown("---")               

# ---------------- Security Dashboard ----------------
elif page == "📊 Security Dashboard":
    st.title("DeepWAF-XAI Security Operations Center")
    st.markdown("### 🔐 Admin Access")
    passkey = st.text_input("Enter Admin Passkey", type="password")
    if passkey != ADMIN_PASSKEY:
        st.warning("Admin authentication required")
        st.stop()
    st.success("Admin Access Granted")
    st_autorefresh(interval=5000, key="refresh")

    # Load logs
    df_logs = load_attack_logs()

    # Filters setup
    attack_type_options = ["All"]
    severity_options = ["All", "CRITICAL", "HIGH", "MEDIUM", "LOW"]
    if not df_logs.empty:
        try:
            df_logs["timestamp"] = pd.to_datetime(df_logs["timestamp"], errors="coerce")
            date_min = df_logs['timestamp'].min().date()
            date_max = df_logs['timestamp'].max().date()
        except Exception as e:
            st.error(f"Error processing timestamps: {e}")
            date_min, date_max = None, None
        try:
            attack_type_options += sorted(df_logs["attack_type"].dropna().unique().tolist())
        except:
            pass
    else:
        date_min, date_max = None, None

    # Date range selector
    if date_min and date_max:
        selected_dates = st.sidebar.date_input("Select Date Range", [date_min, date_max])
        if len(selected_dates) == 2:
            start_date, end_date = selected_dates
            date_range = (pd.to_datetime(str(start_date)), pd.to_datetime(str(end_date)))
        else:
            date_range = None
    else:
        date_range = None

    attack_type_filter = st.sidebar.selectbox("Attack Type", attack_type_options)
    severity_filter = st.sidebar.selectbox("Severity", severity_options)
    request_search = st.sidebar.text_input("Search Request")

    # Move get_filtered_logs outside for clarity
    # Already done above

    filtered_df = get_filtered_logs(df_logs, attack_type_filter, severity_filter, date_range, request_search)

    # Metrics
    total_requests = len(df_logs)
    normal_labels = ["Normal", "LEGAL"]
    malicious_requests = len(df_logs[~df_logs["attack_type"].isin(normal_labels)]) if not df_logs.empty else 0
    safe_requests = len(df_logs[df_logs["attack_type"].isin(normal_labels)]) if not df_logs.empty else 0

    def safe_mean(series):
        return series.mean() if not series.empty and pd.notnull(series).any() else 0

    confidence_avg = safe_mean(df_logs["confidence"]) * 100 if "confidence" in df_logs.columns else 0
    threat_score_avg = safe_mean(df_logs["threat_score"]) if "threat_score" in df_logs.columns else 0
    prediction_time_avg = safe_mean(df_logs["prediction_time_ms"]) if "prediction_time_ms" in df_logs.columns else 0
    critical_count = len(df_logs[df_logs["severity"] == "CRITICAL"]) if "severity" in df_logs.columns else 0
    high_count = len(df_logs[df_logs["severity"] == "HIGH"]) if "severity" in df_logs.columns else 0
    medium_count = len(df_logs[df_logs["severity"] == "MEDIUM"]) if "severity" in df_logs.columns else 0
    low_count = len(df_logs[df_logs["severity"] == "LOW"]) if "severity" in df_logs.columns else 0

    # Show metrics
    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Total Requests", total_requests)
    col2.metric("Safe Requests", safe_requests)
    col3.metric("Malicious Requests", malicious_requests)
    col4.metric("Critical", critical_count)
    col5, col6, col7, col8 = st.columns(4)
    col5.metric("Confidence", f"{confidence_avg:.2f}%")
    col6.metric("Threat Score", f"{threat_score_avg:.2f}")
    col7.metric("Prediction Time", f"{prediction_time_avg:.2f} ms")
    col8.metric("High Severity", high_count)
    col9, col10 = st.columns(2)
    col9.metric("Medium", medium_count)
    col10.metric("Low", low_count)

    # Attack Type Distribution Pie
    if not df_logs.empty and "attack_type" in df_logs.columns:
        try:
            attack_counts = df_logs["attack_type"].value_counts()
            fig_attack = px.pie(
                attack_counts,
                values=attack_counts.values,
                labels=attack_counts.index,
                title="Attack Type Distribution"
            )
            st.plotly_chart(fig_attack)
        except Exception as e:
            st.error(f"Chart Error: {e}")

    # Severity Distribution Pie
    if not df_logs.empty and "severity" in df_logs.columns:
        try:
            severity_counts = df_logs["severity"].value_counts()
            fig_severity = px.pie(
                severity_counts,
                values=severity_counts.values,
                labels=severity_counts.index,
                title="Severity Distribution"
            )
            st.plotly_chart(fig_severity)
        except Exception as e:
            st.error(f"Chart Error: {e}")

    # Attacks over time
    if not df_logs.empty:
        try:
            df_logs["timestamp"] = pd.to_datetime(df_logs["timestamp"], errors="coerce")
            df_logs = df_logs.dropna(subset=["timestamp"])
            df_logs['date'] = pd.DatetimeIndex(df_logs['timestamp']).date
            time_series = df_logs.groupby('date').size().reset_index(name='counts')
            fig_time = px.line(time_series, x='date', y='counts', title='Attacks Over Time')
            st.plotly_chart(fig_time)
        except Exception as e:
            st.error(f"Chart Error: {e}")

    # Histograms
    if "confidence" in df_logs.columns:
        try:
            fig_confidence = px.histogram(df_logs, x='confidence', nbins=20, title='Confidence Scores Distribution')
            st.plotly_chart(fig_confidence)
        except Exception as e:
            st.error(f"Chart Error: {e}")
    if "prediction_time_ms" in df_logs.columns:
        try:
            fig_pred_time = px.histogram(df_logs, x='prediction_time_ms', nbins=20, title='Prediction Time Distribution (ms)')
            st.plotly_chart(fig_pred_time)
        except Exception as e:
            st.error(f"Chart Error: {e}")

    # Threat Score by Attack Type
    if "attack_type" in df_logs.columns and "threat_score" in df_logs.columns:
        try:
            threat_by_type = df_logs.groupby('attack_type')['threat_score'].mean().reset_index()
            fig_threat = px.bar(
                threat_by_type,
                x='attack_type',
                y='threat_score',
                title='Average Threat Score by Attack Type'
            )
            st.plotly_chart(fig_threat)
        except Exception as e:
            st.error(f"Chart Error: {e}")

    # Attack Logs Table
    display_cols = ['timestamp', 'request', 'attack_type', 'confidence', 'severity', 'threat_score', 'prediction_time_ms']
    for col in display_cols:
        if col not in filtered_df.columns:
            filtered_df[col] = ''
    st.markdown("### Attack Logs")
    st.dataframe(filtered_df[display_cols].sort_values(by='timestamp', ascending=False))

    # CSV export
    csv_data = filtered_df.to_csv(index=False).encode("utf-8")
    st.download_button("Download Attack Logs as CSV", data=csv_data, file_name="attack_logs.csv", mime="text/csv")

    # Attack Map (simulated)
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
    attack_map_data = []
    for _, row in filtered_df.iterrows():
        if row["attack_type"] not in ["Normal", "LEGAL"]:
            country = random.choice(countries)
            attack_map_data.append({
                "country": country[0],
                "lat": country[1],
                "lon": country[2],
                "attack": row["attack_type"]
            })
    if attack_map_data:
        df_map = pd.DataFrame(attack_map_data)
        try:
            fig_map = px.scatter_geo(
                df_map,
                lat="lat",
                lon="lon",
                color="attack",
                hover_name="country",
                projection="natural earth"
            )
            fig_map.update_traces(marker=dict(size=14, opacity=0.9))
            st.plotly_chart(fig_map)
        except Exception as e:
            st.error(f"Map Chart Error: {e}")
    else:
        st.info("No malicious attacks recorded yet.")