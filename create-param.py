import os
import sys
import mysql.connector
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives import serialization
import base64

# Configuration
DB_CONFIG = {
    'user': 'changeme_user',
    'password': 'changeme',
    'host': 'localhost',
    'database': 'vault_ddbb'
}
BASE_DIR = "/opt/vault/ssl"

# Function to create and encrypt parameter
def create_param(client_name, param_name, param_value):

    # Connect to DB
    connection = mysql.connector.connect(**DB_CONFIG)
    cursor = connection.cursor()

    try:
        # Retrieve client ID
        cursor.execute("SELECT id_cli_int FROM clients WHERE nom_cli_vch = %s", (client_name,))
        client = cursor.fetchone()

        if not client:
            print(f"Client '{client_name}' not found.")
            return

        client_id = client[0]

        # Load public key
        public_key_path = os.path.join(BASE_DIR, str(client_id), "public_key.pem")
        with open(public_key_path, "rb") as f:
            public_key = serialization.load_pem_public_key(f.read())

        # Ensure proper padding and encryption
        encrypted_param_value = public_key.encrypt(
            param_value.encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=SHA256()),
                algorithm=SHA256(),
                label=None
            )
        )

        # Encode encrypted value in Base64 for storage
        encrypted_value_b64 = base64.b64encode(encrypted_param_value).decode()

        # Save the parameter in the database
        cursor.execute(
            "INSERT INTO params (nom_par_vch, val_par_vch, id_cli_int) VALUES (%s, %s, %s)",
            (
                param_name,
                encrypted_value_b64,
                client_id
            )
        )
        connection.commit()

        print(f"Parameter '{param_name}' created successfully for client '{client_name}'.")
    finally:
        cursor.close()
        connection.close()

# Main script logic
if __name__ == "__main__":
    if len(sys.argv) < 4:
        print("Usage: python3 create-param.py <client_name> <param_name> <param_value>")
        sys.exit(1)

    client_name = sys.argv[1]
    param_name = sys.argv[2]
    param_value = sys.argv[3]

    create_param(client_name, param_name, param_value)
