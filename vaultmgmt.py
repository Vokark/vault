import os
import sys
import random
import string
import passlib
import secrets
import passlib.hash
import mysql.connector
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

# Configuration
DB_CONFIG = {
    'user': 'changeme_user',
    'password': 'changeme_user',
    'host': 'localhost',
    'database': 'vault_ddbb'
}
BASE_DIR = "/opt/vault/ssl"
CSR_DIR = "/opt/vault/certs/csr/"
VAULT_BASE_DIR = "/opt/vault"
CERTS_PRIVATE_DIR = "/opt/vault/certs/private/"
CERTS_PUBLIC_DIR = "/opt/vault/certs/public/"
SERVER_PRIVATE_DIR = "/opt/vault/certs/server/private/"
SERVER_PUBLIC_DIR = "/opt/vault/certs/server/public/"
ROOT_CA_PUBLIC_DIR = "/opt/vault/certs/ca/public/"
ROOT_CA_PRIVATE_DIR = "/opt/vault/certs/ca/private/"
VAULT_DOMAIN = ".example.com"
VAULT_NAME = "vault"
# Function to create directories
def create_directory(path):
    os.makedirs(path, exist_ok=True)

# Function to generate SSL certificates
def generate_ssl(client_id):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    private_key_path = os.path.join(BASE_DIR, f"{client_id}", "private_key.pem")
    public_key_path = os.path.join(BASE_DIR, f"{client_id}", "public_key.pem")

    # Save private key
    with open(private_key_path, "wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            )
        )

    # Save public key
    public_key = private_key.public_key()
    with open(public_key_path, "wb") as f:
        f.write(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )

    print(f"Keys generated for client {client_id} and saved in {os.path.join(BASE_DIR, str(client_id))}")
# Function to generate SSL certificates
def generate_ssl(client_id):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    private_key_path = os.path.join(BASE_DIR, f"{client_id}", "private_key.pem")
    public_key_path = os.path.join(BASE_DIR, f"{client_id}", "public_key.pem")

    # Save private key
    with open(private_key_path, "wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            )
        )

    # Save public key
    public_key = private_key.public_key()
    with open(public_key_path, "wb") as f:
        f.write(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )
    print(f"Keys generated for client {client_id} and saved in {os.path.join(BASE_DIR, str(client_id))}")

#api_key sha512 hash generation:
def generateHash(apikey, salt_len=8, iterations=65000):
    result = passlib.hash.sha512_crypt.using(salt=secrets.token_hex(salt_len), rounds=iterations).hash(apikey)
    return result

# Function to add client
def add_client(client_name):

    # Connect to DB
    connection = mysql.connector.connect(**DB_CONFIG)
    cursor = connection.cursor()

    try:
        # Check if client already exists
        cursor.execute("SELECT id_cli_int FROM clients WHERE nom_cli_vch = %s", (client_name,))
        existing_client = cursor.fetchone()

        if existing_client:
            return "error Client Exists"

        # Insert client into DB
        cursor.execute("INSERT INTO clients (nom_cli_vch,lvl_cli_int) VALUES (%s,3)", (client_name,))
        connection.commit()
        client_id = cursor.lastrowid
        client_dir = os.path.join(BASE_DIR, str(client_id))
        create_directory(client_dir)

        # Generate API keys id 8-8, key 4-8-4-8-8
        api_id = ''.join(random.choices(string.ascii_letters + string.digits, k=8) + list('-') + random.choices(string.ascii_letters + string.digits, k=8))
        api_key = ''.join(random.choices(string.ascii_letters + string.digits, k=4) + list('-') + random.choices(string.ascii_letters + string.digits, k=8) + list('-') + random.choices(string.ascii_letters + string.digits, k=4) + list('-') + random.choices(string.ascii_letters + string.digits, k=8) + list('-') + random.choices(string.ascii_letters + string.digits, k=8))

        # Generate SSL keys
        generate_ssl(client_id)
        hashedkey = generateHash(api_key)

        # Insert into apis table
        cursor.execute(
            "INSERT INTO apis (id_api_vch, key_api_vch, id_cli_int) VALUES (%s, %s, %s)",
            (api_id, hashedkey, client_id)
        )
        connection.commit()

        print(f"Client {client_name} added successfully.")
        print(f"API ID: {api_id}")
        print(f"API KEY: {api_key}")
    finally:
        cursor.close()
        connection.close()

# Main script logic
if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python3 clientadd.py <add|generate_ssl> <client_name>")
        sys.exit(1)

    action = sys.argv[1]
    client_name = sys.argv[2]

    if action == "add":
        add_client(client_name)
    elif action == "generate_ssl":
        sanitized_name = client_name.replace(" ", "-")
        generate_ssl(sanitized_name)
    else:
        print("Invalid action. Use 'add' or 'generate_ssl'.")
