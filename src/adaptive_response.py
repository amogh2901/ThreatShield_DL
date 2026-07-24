def adaptive_response(severity):

    if severity == "CRITICAL":
        return "Block IP immediately"

    elif severity == "HIGH":
        return "Rate limit request"

    else:
        return "Monitor activity"