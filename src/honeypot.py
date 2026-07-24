# Define a set of honeypot endpoints for efficient lookup
HONEYPOT_PATHS = {
    "/admin",
    "/administrator",
    "/config",
    "/secret",
    "/hidden",
    "/backup",
    "/backup.zip",
    "/database",
    "/db",
    "/phpmyadmin",
    "/wp-admin",
    "/wp-login.php",
    "/server-status",
    "/cgi-bin",
    "/.env",
    "/robots.txt"
}

def check_honeypot(request):
    # Handle non-string or None inputs safely
    if not isinstance(request, str):
        return False

    # Normalize the request string
    request = request.lower().strip()

    # Check if any honeypot path is contained in the request
    return any(path in request for path in HONEYPOT_PATHS)