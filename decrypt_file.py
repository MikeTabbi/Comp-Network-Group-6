from cryptography.fernet import Fernet

# Step 1: Load the secret key
with open("secret.key", "rb") as key_file:
    key = key_file.read()

# Step 2: Load the encrypted file
with open("message.encrypted", "rb") as enc_file:
    encrypted = enc_file.read()

# Step 3: Decrypt the contents
fernet = Fernet(key)
decrypted = fernet.decrypt(encrypted)

# Step 4: Save the decrypted content
with open("message_decrypted.txt", "wb") as dec_file:
    dec_file.write(decrypted)

print("✅ File decrypted and saved as message_decrypted.txt")
