import sqlite3
import os
import logging
from datetime import datetime


# Set up a logger for the module
logger = logging.getLogger(__name__)

def log_attack(
    request,
    attack_type,
    confidence=0.0,
    severity="LOW",
    threat_score=0.0,
    prediction_time_ms=0.0
):
    """
    Logs attack details into the SQLite database 'database/logs.db'.
    Creates the database directory and table if they do not exist.
    Adds missing optional columns without affecting existing data.
    """
    db_path = "database/logs.db"
    try:
        # Ensure the directory for the database exists
        os.makedirs(os.path.dirname(db_path), exist_ok=True)

        # Connect to the database using a context manager
        with sqlite3.connect(db_path) as conn:
            cursor = conn.cursor()

            # Create table if it doesn't exist, with the initial schema
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS attack_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT,
                    request TEXT,
                    attack_type TEXT
                )
            """)

            # Retrieve existing columns
            cursor.execute("PRAGMA table_info(attack_logs)")
            existing_columns = [info[1] for info in cursor.fetchall()]

            # Optional columns that may need to be added
            optional_columns = {
                "confidence": "REAL",
                "severity": "TEXT",
                "threat_score": "REAL",
                "prediction_time_ms": "REAL"
            }

            # Add missing optional columns
            for column_name, column_type in optional_columns.items():
                if column_name not in existing_columns:
                    try:
                        cursor.execute(f"ALTER TABLE attack_logs ADD COLUMN {column_name} {column_type}")
                        logger.info(f"Added missing column: {column_name}")
                    except sqlite3.Error as e:
                        logger.error(f"Error adding column {column_name}: {e}")

            # Insert the attack log with all parameters
            timestamp_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            cursor.execute("""
                INSERT INTO attack_logs (
                    timestamp,
                    request,
                    attack_type,
                    confidence,
                    severity,
                    threat_score,
                    prediction_time_ms
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                timestamp_str,
                request,
                attack_type,
                confidence,
                severity,
                threat_score,
                prediction_time_ms
            ))

            # Commit the transaction
            conn.commit()

            logger.info("Attack logged successfully.")

        return True

    except sqlite3.Error as e:
        # Log SQLite errors
        logger.error(f"SQLite error: {e}")
        return False
    except Exception as e:
        # Log any other unexpected errors
        logger.error(f"Unexpected error: {e}")
        return False