import random

attacks = [
    "<script>alert(1)</script>",
    "id=1 OR 1=1",
    "../../etc/passwd",
    "https://google.com"
]

def generate_attack():

    return random.choice(attacks)