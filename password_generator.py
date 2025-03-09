import streamlit as st
import random
import string
import re
import pyperclip
import pandas as pd
import time
import pyotp  # For 2FA
import base64  # For encoding secret keys
from cryptography.fernet import Fernet  # For AES encryption

# Generate a secret key for encryption (This should be stored securely)
SECRET_KEY = Fernet.generate_key()
cipher = Fernet(SECRET_KEY)

# Function to encrypt password
def encrypt_password(password):
    return cipher.encrypt(password.encode()).decode()

# Function to decrypt password
def decrypt_password(encrypted_password):
    return cipher.decrypt(encrypted_password.encode()).decode()

# Function to generate a random password
def generate_password(length, use_digits, use_special_chars, pronounceable):
    if pronounceable:
        vowels = "aeiou"
        consonants = "".join(set(string.ascii_lowercase) - set(vowels))
        password = [random.choice(consonants) if i % 2 == 0 else random.choice(vowels) for i in range(length)]
        return "".join(password)

    characters = string.ascii_letters + (string.digits if use_digits else "") + (string.punctuation if use_special_chars else "")
    password = [random.choice(characters) for _ in range(length)]
    random.shuffle(password)
    return "".join(password)

# Function to calculate entropy of a password
def calculate_entropy(password):
    char_set_size = 0
    if any(c.islower() for c in password): char_set_size += 26
    if any(c.isupper() for c in password): char_set_size += 26
    if any(c.isdigit() for c in password): char_set_size += 10
    if any(c in string.punctuation for c in password): char_set_size += len(string.punctuation)
    
    entropy = len(password) * (char_set_size.bit_length())
    return entropy

# Function to check password strength
def check_password_strength(password):
    score, feedback = 0, []
    if len(password) >= 8: score += 1
    else: feedback.append("Make your password at least 8 characters long.")
    
    if re.search(r'[A-Z]', password): score += 1
    else: feedback.append("Include at least one uppercase letter (A-Z).")
    
    if re.search(r'[a-z]', password): score += 1
    else: feedback.append("Include at least one lowercase letter (a-z).")
    
    if re.search(r'\d', password): score += 1
    else: feedback.append("Include at least one number (0-9).")
    
    if re.search(r'[!@#$%^&*(),.?":{}|<>]', password): score += 1
    else: feedback.append("Include at least one special character (!@#$%^&*).")

    entropy = calculate_entropy(password)
    strength = "✅ **Strong**" if score == 5 else "⚠️ **Moderate**" if score >= 3 else "❌ **Weak**"
    return score, strength, feedback, entropy

# Function to generate a 2FA code
def generate_2fa_code():
    secret = base64.b32encode(random.randbytes(10)).decode('utf-8')  # Generate random secret key
    totp = pyotp.TOTP(secret)  # Generate OTP
    return totp.now(), secret

# Streamlit UI
st.set_page_config(page_title="Ultimate Password Generator", page_icon="🔐")

st.title("🔐 Ultimate Password Generator & Security Toolkit")

# User Inputs
length = st.slider("Password Length", min_value=8, max_value=30, value=12)
use_digits = st.checkbox("Include Numbers (0-9)", value=True)
use_special_chars = st.checkbox("Include Special Characters (@, #, !, etc.)", value=True)
pronounceable = st.checkbox("Generate Pronounceable Passwords", value=False)
num_passwords = st.number_input("Number of Passwords to Generate", min_value=1, max_value=10, value=1)

# Generate Passwords
if st.button("Generate Password(s)"):
    passwords = [generate_password(length, use_digits, use_special_chars, pronounceable) for _ in range(num_passwords)]
    
    st.subheader("Generated Password(s)")
    for idx, password in enumerate(passwords, start=1):
        encrypted_password = encrypt_password(password)
        hidden = st.checkbox(f"Show Password {idx}", key=f"show_{idx}")
        st.write(f"🔑 **Password {idx}:** `{password if hidden else '********'}`")
        st.write(f"🔒 **Encrypted:** `{encrypted_password}`")

        # Copy to clipboard button
        if st.button(f"Copy Password {idx}", key=f"copy_{idx}"):
            pyperclip.copy(password)
            st.success(f"Password {idx} copied to clipboard!")

    # Save passwords to CSV
    df = pd.DataFrame({"Passwords": passwords, "Encrypted": [encrypt_password(p) for p in passwords]})
    df.to_csv("passwords.csv", index=False)
    with open("passwords.csv", "rb") as file:
        st.download_button(label="📥 Download Passwords", data=file, file_name="passwords.csv", mime="text/csv")

# Check Password Strength
st.subheader("🔍 Check Your Own Password")
user_password = st.text_input("Enter a password to check its strength", type="password")

if user_password:
    score, strength, feedback, entropy = check_password_strength(user_password)
    st.write(f"**Strength:** {strength}")
    st.write(f"**Entropy Score:** {entropy:.2f} (Higher is better)")
    
    if feedback:
        st.subheader("Suggestions to Improve Your Password")
        for suggestion in feedback:
            st.write(f"🔹 {suggestion}")

# Generate 2FA Code
st.subheader("🔑 Generate 2FA Code (One-Time Password)")
if st.button("Generate 2FA Code"):
    otp, secret = generate_2fa_code()
    st.write(f"**Your OTP:** `{otp}`")
    st.write(f"**Secret Key:** `{secret}`")
    st.success("Use this key with Google Authenticator!")

# Password History
st.subheader("📜 Password History")
if st.button("View Saved Passwords"):
    try:
        df = pd.read_csv("passwords.csv")
        df["Decrypted"] = df["Encrypted"].apply(decrypt_password)
        st.dataframe(df[["Passwords", "Decrypted"]])
    except Exception as e:
        st.error("No saved passwords found!")
