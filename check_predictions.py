from src.detector import detect_attack

tests = [
    "SELECT * FROM users WHERE id=1",
    "<script>alert(1)</script>",
    "../../etc/passwd",
    "https://paypal-login-security.com",
    "hello world"
]

for t in tests:
    attack, conf, probs = detect_attack(t)

    print("=" * 60)
    print("Input:", t)
    print("Attack:", attack)
    print("Confidence:", conf)
    print("Probabilities:", probs)