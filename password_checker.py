import math
import re

def calculate_entropy(password: str) -> float:
    """Estimate entropy based on character set size and length."""
    charset = 0
    if re.search(r"[a-z]", password):
        charset += 26
    if re.search(r"[A-Z]", password):
        charset += 26
    if re.search(r"[0-9]", password):
        charset += 10
    if re.search(r"[^a-zA-Z0-9]", password):
        charset += 32  # special characters

    if charset == 0:
        return 0
    return len(password) * math.log2(charset)


def check_strength(password: str) -> dict:
    """Return strength level and suggestions."""
    entropy = calculate_entropy(password)
    suggestions = []

    if len(password) < 8:
        suggestions.append("Increase length to at least 8 characters.")
    if not re.search(r"[A-Z]", password):
        suggestions.append("Add uppercase letters.")
    if not re.search(r"[a-z]", password):
        suggestions.append("Add lowercase letters.")
    if not re.search(r"[0-9]", password):
        suggestions.append("Include numbers.")
    if not re.search(r"[^a-zA-Z0-9]", password):
        suggestions.append("Include special characters (!,@,#,$, etc.).")

    if entropy < 28:
        strength = "Weak"
    elif entropy < 36:
        strength = "Moderate"
    elif entropy < 60:
        strength = "Strong"
    else:
        strength = "Very Strong"

    return {
        "password": password,
        "entropy": round(entropy, 2),
        "strength": strength,
        "suggestions": suggestions if suggestions else ["Your password looks good!"]
    }
