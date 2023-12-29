from Crypto.Cipher import Blowfish
from Crypto.Random import get_random_bytes
from base64 import b64encode, b64decode
import json
import os

def encrypt_data(key, data):
    cipher = Blowfish.new(key, Blowfish.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return b64encode(cipher.nonce + tag + ciphertext).decode('utf-8')

def decrypt_data(key, token):
    try:
        data = b64decode(token)
        nonce, tag, ciphertext = data[:16], data[16:32], data[32:]
        cipher = Blowfish.new(key, Blowfish.MODE_EAX, nonce)
        return cipher.decrypt_and_verify(ciphertext, tag)
    except ValueError as e:
        print(f"Decryption error: {e}")
        return False

def load_vault(password):
    if not os.path.exists('vault.json'):
        return {}
    with open('vault.json', 'r') as file:
        encrypted_data = file.read()
        decrypted_data = decrypt_data(password.encode(), encrypted_data)
        if decrypted_data:
            return json.loads(decrypted_data)
        else:
            print("Incorrect password or corrupted vault.")
            return None

def save_vault(password, data):
    encrypted_data = encrypt_data(password.encode(), json.dumps(data).encode())
    with open('vault.json', 'w') as file:
        file.write(encrypted_data)

def main():
    password = input("Enter your vault password: ")
    vault = load_vault(password)
    if vault is None:
        return

    while True:
        print("\n1. Store a new password\n2. Retrieve a password\n3. Exit")
        choiq   

        if choice == '1':
            site = input("Enter the site name: ")
            site_password = input("Enter the password for the site: ")
            vault[site] = encrypt_data(password.encode(), site_password.encode())
            save_vault(password, vault)
            print("Password saved.")

        elif choice == '2':
            site = input("Enter the site name: ")
            if site in vault:
                decrypted_password = decrypt_data(password.encode(), vault[site])
                if decrypted_password:
                    print(f"Password for {site}: {decrypted_password.decode()}")
                else:
                    print("Error decrypting the password.")
            else:
                print("No password found for this site.")

        elif choice == '3':
            break
        else:
            print("Invalid option, please try again.")

if __name__ == "__main__":
    main()
