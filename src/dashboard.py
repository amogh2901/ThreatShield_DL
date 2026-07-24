import streamlit as st
import sqlite3
import pandas as pd

st.title("ThreatShield Security Operations Dashboard")

conn = sqlite3.connect("database/logs.db")

df = pd.read_sql_query("SELECT * FROM attack_logs", conn)

st.subheader("Total Attacks Detected")

st.metric("Total Attacks", len(df))

st.subheader("Recent Attack Logs")

st.dataframe(df.tail(10))

st.subheader("Attack Distribution")

attack_counts = df['attack_type'].value_counts()

st.bar_chart(attack_counts)