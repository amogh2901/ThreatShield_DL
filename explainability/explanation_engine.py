"""
ThreatShield Explainability Module
----------------------------------
Provides human-readable explanations for Deep Learning predictions.

This module DOES NOT modify the prediction.
It only explains why the prediction was made.
"""


class ExplanationEngine:
    """Generate human-readable explanations for ThreatShield predictions."""

    def __init__(self):
        pass

    def explain(self, payload: str, prediction: str, confidence: float):
        """
        Generate explanation for a prediction.

        Parameters
        ----------
        payload : str
            Incoming HTTP request or URL.

        prediction : str
            Predicted attack class.

        confidence : float
            Model confidence.

        Returns
        -------
        dict
            Explanation dictionary.
        """

        payload = payload.lower().strip()

        reasons = []
        explanation_text = ""
        risk_level = "LOW"

        # ---------------- SQL Injection ----------------
        if prediction == "SQL Injection":

            risk_level = "HIGH"

            if "union" in payload:
                reasons.append("UNION keyword detected")

            if "select" in payload:
                reasons.append("SELECT keyword detected")

            if "or 1=1" in payload:
                reasons.append("Authentication bypass pattern detected")

            if "drop table" in payload:
                reasons.append("Dangerous SQL command detected")

            explanation_text = (
                "The Bi-Directional LSTM model classified this request as "
                "SQL Injection because it detected SQL query manipulation "
                "patterns commonly used to access or modify databases."
            )

        # ---------------- Cross Site Scripting ----------------
        elif prediction == "Cross Site Scripting":

            risk_level = "HIGH"

            if "<script>" in payload:
                reasons.append("Executable JavaScript detected")

            if "alert(" in payload:
                reasons.append("Suspicious JavaScript function found")

            explanation_text = (
                "The Bi-Directional LSTM model detected executable "
                "JavaScript code that may be used to perform a "
                "Cross-Site Scripting (XSS) attack."
            )

        # ---------------- Path Traversal ----------------
        elif prediction == "Path Traversal":

            risk_level = "HIGH"

            if "../" in payload:
                reasons.append("Directory traversal pattern detected")

            explanation_text = (
                "The request contains directory traversal sequences "
                "that may allow unauthorized access to sensitive files."
            )

        # ---------------- Phishing ----------------
        elif prediction == "Phishing URL":

            risk_level = "MEDIUM"

            reasons.append("Suspicious URL characteristics detected")

            explanation_text = (
                "The Deep Learning model identified characteristics "
                "commonly associated with phishing websites, such as "
                "deceptive URLs and suspicious structures."
            )

        # ---------------- Normal ----------------
        else:

            risk_level = "LOW"

            reasons.append("No malicious attack patterns detected")

            explanation_text = (
                "The Bi-Directional LSTM model did not detect any "
                "known malicious patterns. The request appears to be legitimate."
            )

        # Confidence interpretation
        if confidence >= 0.95:
            confidence_level = "Very High"
        elif confidence >= 0.85:
            confidence_level = "High"
        elif confidence >= 0.70:
            confidence_level = "Medium"
        else:
            confidence_level = "Low"

        # Recommended action
        if risk_level == "HIGH":
            recommended_action = (
                "Immediately block the request, log the event, "
                "and notify the administrator."
            )

        elif risk_level == "MEDIUM":
            recommended_action = (
                "Monitor the request and perform additional verification."
            )

        else:
            recommended_action = (
                "Allow the request and continue normal monitoring."
            )

        return {

            "prediction": prediction,

            "confidence": round(confidence * 100, 2),

            "confidence_level": confidence_level,

            "risk_level": risk_level,

            "summary": explanation_text,

            "explanation": reasons,

            "recommended_action": recommended_action

        }