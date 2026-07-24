def calculate_threat_score(severity, confidence=0.5):
    severity = severity.upper()

    base_scores = {
        "LOW": 20,
        "MEDIUM": 50,
        "HIGH": 75,
        "CRITICAL": 95
    }

    # Get the base score, default to 40 if severity is unknown
    base = base_scores.get(severity, 40)

    # Clamp confidence to [0.0, 1.0]
    confidence = max(0.0, min(confidence, 1.0))

    # Calculate adjusted score
    score = base + (confidence * 20)

    # Cap the score at 100
    if score > 100:
        score = 100

    # Normalize to [0.0, 1.0] and round to 2 decimal places
    normalized_score = round(score / 100, 2)

    return normalized_score