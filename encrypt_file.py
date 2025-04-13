from cryptography.fernet import Fernet

# Step 1: Generate a key and save it
key = Fernet.generate_key()
with open("secret.key", "wb") as key_file:
    key_file.write(key)

# Step 2: Load the key
with open("secret.key", "rb") as key_file:
    key = key_file.read()

# Step 3: Encrypt the file
fernet = Fernet(key)

with open("message.txt", "rb") as file:
    original = file.read()

encrypted = fernet.encrypt(original)

with open("message.encrypted", "wb") as encrypted_file:
    encrypted_file.write(encrypted)

print("✅ File encrypted and saved as message.encrypted")
