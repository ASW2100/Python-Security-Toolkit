import re
import math
import getpass

COMMON_PASSWORDS = {
    "123456", "password", "123456789", "qwerty", "abc123",
    "letmein", "iloveyou", "admin", "welcome", "monkey"
}

def calculate_entropy(password: str) -> float:
    charset_size = 0
    if re.search(r"[a-z]", password): charset_size += 26
    if re.search(r"[A-Z]", password): charset_size += 26
    if re.search(r"[0-9]", password): charset_size += 10
    if re.search(r"[!@#$%^&*(),.?\":{}|<>]", password): charset_size += 32
    if re.search(r"[ ]", password): charset_size += 1  # Include spaces in charset size

    if charset_size == 0:
        return 0.0

    return len(password) * math.log2(charset_size)

def evaluate_password(password: str) -> str:
    if password in COMMON_PASSWORDS:
        return "Very Weak – Common password"

    entropy = calculate_entropy(password)
    length = len(password)

    if length < 6:
        return "Very Weak – Too short"
    elif entropy < 28:
        return "Weak – Low entropy"
    elif entropy < 36:
        return "Moderate – Could be stronger"
    elif entropy < 60:
        return "Strong – Good protection"
    else:
        return "Very Strong – High entropy"

def run():
    print("""
🔐 CyberSecBox - Password Strength Checker
    """)
    password = getpass.getpass("Enter password to evaluate: ")
    if not password:
        print("\nError: Password cannot be empty.")
        return

    rating = evaluate_password(password)
    entropy = calculate_entropy(password)
    print(f"\nStrength: {rating}\nEntropy: {entropy:.2f} bits\n")

if __name__ == "__main__":
    run()

