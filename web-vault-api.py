import os
import sys
import re
import base64
import logging
import secrets
import random
import string
import datetime
import subprocess
import socket
import logging.handlers
import mysql.connector
import passlib.hash
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from redis import Redis
from gunicorn.app.base import BaseApplication
from gunicorn.glogging import Logger
from flask_limiter import Limiter
from flask import Flask, request, jsonify
from werkzeug.middleware.proxy_fix import ProxyFix

# Base parameters:
# You can obtain from environmet or the values on the right can be changed.

# SSL Template parameter
ssl_template = {
    "C": "CL",
    "ST": "RM",
    "L": "Santiago",
    "O": "Organization",
    "OU": "Organization Unit"
}

# Default Directories, validate if user that run this program have right access to directories. Avoid to use root.
# Remember to use persistent storage for cert dirs if you use dockers.
MASTER_CERT_PASSWORD = os.getenv('MASTER_PASSWORD', 'certpass_changeme') # For future use
VAULT_BASE_DIR = "/opt/vault"
CSR_DIR = f"{VAULT_BASE_DIR}/certs/csr/"
CERTS_PRIVATE_DIR = f"{VAULT_BASE_DIR}/certs/private/"
CERTS_PUBLIC_DIR = f"{VAULT_BASE_DIR}/certs/public/"
SERVER_PRIVATE_DIR = f"{VAULT_BASE_DIR}/certs/server/private/"
SERVER_PUBLIC_DIR = f"{VAULT_BASE_DIR}/certs/server/public/"
ROOT_CA_PUBLIC_DIR = f"{VAULT_BASE_DIR}/certs/ca/public/"
ROOT_CA_PRIVATE_DIR = f"{VAULT_BASE_DIR}/certs/ca/private/"
VAULT_DOMAIN = ".example.com"
VAULT_NAME = "vault"
BASE_DIR = f"{VAULT_BASE_DIR}/certs" # Clients cert directory.
TRUSTED_PROXIES = ["192.168.1.1", "192.168.2.1"] # All Trusted reverse proxies.
SYSLOG_SERVER = os.getenv('SYSLOG_SERVER', 'syslog.example.com')  # You can use server address or IP, change it or your application won't start.
SYSLOG_PORT = os.getenv('SYSLOG_PORT', '514')
LIMITER_CONFIG = "5 per minute" # Limits to 5 requests per minute from same IP address, cam be change at any endpoint manualy.

# DB parameters
DB_CONFIG = {
    'host': os.getenv('DB_HOST', 'localhost'),
    'user': os.getenv("DB_USER", 'change_user'),
    'password': os.getenv("DB_PASSWORD", 'changeme'),
    'database': os.getenv("DB_NAME", 'vault_ddbb')
}


# Gunicorn Class
class GunicornApp(BaseApplication):
    def __init__(self, app, options=None):
        self.app = app
        self.options = options or {}
        super().__init__()

    def load_config(self):
        # Gunicorn configuration
        for key, value in self.options.items():
            if key in self.cfg.settings and value is not None:
                self.cfg.set(key, value)
        self.cfg.set("logger_class", FlaskGunicornLogger)  # Use flask logger

    def load(self):
        return self.app

# Logger Class
class FlaskGunicornLogger(Logger):
    def setup(self, cfg):
        # Use the flask logger configured in application
        self.error_log = logging.getLogger('werkzeug')
        self.access_log = logging.getLogger('werkzeug')
        self.error_log.setLevel(logging.INFO)
        self.access_log.setLevel(logging.INFO)

# Change permision for dir
def set_secure_permissions(base_path):
    """
    Stablish 700 permission for directories and 600 for file in al sub-directories.
    
    :param base_path: Base path.
    """
    if not os.path.exists(base_path):
        logging.error(f"Error: Cannot change permissions on a non-existent directory {base_path}.")
        print(f"Error: Cannot change permissions on a non-existent directory {base_path}.")
        return

    for root, dirs, files in os.walk(base_path):
        # Establecer permisos 700 para directorios
        for directory in dirs:
            dir_path = os.path.join(root, directory)
            try:
                os.chmod(dir_path, 0o700)
            except PermissionError:
                logging.warning(f"Warning: Directory permissions cannot be changed in dir: {dir_path}")
                print(f"Warning: Directory permissions cannot be changed in dir: {file_path}")

        # Establecer permisos 600 para archivos
        for file in files:
            file_path = os.path.join(root, file)
            try:
                os.chmod(file_path, 0o600)
            except PermissionError:
                logging.warning(f"Warning: File permissions cannot be changed for file: {file_path}")
                print(f"Warning: Warning: File permissions cannot be changed for file {file_path}")

# X-Forwarded-For IP address
def get_client_ip():
    # Get X-Forwarded-For IP Address if available
    if request.remote_addr in TRUSTED_PROXIES:
        xff = request.headers.getlist("X-Forwarded-For")  # Take first IP fron XFF list (real client)
        if xff and re.match(r"^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$", xff[0]):  # IP Format Validation
            return xff[0]
    return request.remote_addr    # Fallback to normal IP if XFF is not available at header.

# Close on root execution:
if os.geteuid() == 0:
    print("Error: Running programs as root is dangerous, please, don't do it!!!.")
    sys.exit(1)

# GET System IP address Can be avoided if you don't need it.
def get_system_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0)
        s.connect(("10.255.255.255", 1))
        ip_address = s.getsockname()[0]
        s.close()
        return ip_address
    except Exception as e:
        raise Exception(f"Failed to retrieve system IP Address: {e}")
local_ip = get_system_ip()

# Validate needed directories and create them if they do not exist.
def ensure_directories():
    os.makedirs(CERTS_PRIVATE_DIR, exist_ok=True)
    os.makedirs(CERTS_PUBLIC_DIR, exist_ok=True)
    os.makedirs(SERVER_PUBLIC_DIR, exist_ok=True)
    os.makedirs(SERVER_PUBLIC_DIR, exist_ok=True)
    os.makedirs(ROOT_CA_PUBLIC_DIR, exist_ok=True)
    os.makedirs(ROOT_CA_PRIVATE_DIR, exist_ok=True)
    os.makedirs(CSR_DIR, exist_ok=True)

# Loggin configuration to send logs to external syslog server
def configure_logging():

    logger = logging.getLogger()
    logger.setLevel(logging.INFO)

    syslog_handler = logging.handlers.SysLogHandler(address=(SYSLOG_SERVER, int(SYSLOG_PORT)))
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    syslog_handler.setFormatter(formatter)

    logger.addHandler(syslog_handler)
    logging.info(f"Logging configured to send logs to a remote syslog server: {SYSLOG_SERVER}:{SYSLOG_PORT}.")

# Flask Configuration
app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1)

# Flask Limiter with X-Forwarded-For IP Address
# Redis configuration as Flask-Limiter backend to avoid DDoS attacks
redis_client = Redis(host="localhost", port=6379, db=0, decode_responses=True)

limiter = Limiter(
    key_func=get_client_ip,  # Uses client IP obtained from XFF or source IP address if no XFF header is available.
    # Uses redis storage.
    storage_uri="redis://localhost:6379"
)

# Function to create directories
def create_directory(path):
    os.makedirs(path, exist_ok=True)

# Input security Validation
def is_valid_input(value, pattern="^[a-zA-Z0-9][a-zA-Z0-9._-]{0,50}$", max_length=50):
    # Validate if value meets the Regular expression criteria and lengt limit,
    # if you need more than 50 characters, use your own regexp pattern
    return bool(re.match(pattern, value)) and len(value) <= max_length

# SSL Functions
# Function to validate the existence of SSL certificate
def validate_server_certificate():
    # Validate the existence of Server SSL certificate
    server_key_path = os.path.join(SERVER_PRIVATE_DIR, f"{VAULT_NAME}{VAULT_DOMAIN}.key")
    server_crt_path = os.path.join(SERVER_PUBLIC_DIR, f"{VAULT_NAME}{VAULT_DOMAIN}.crt")
    if not os.path.exists(server_crt_path) or not os.path.exists(server_key_path):
        create_certificate(VAULT_NAME, is_server=True, validity_days=3650, root_ca=True)

    # Validate the existence of WEB SSL certificate
    web_cert_key_path = os.path.join(SERVER_PRIVATE_DIR, f"{VAULT_NAME}{VAULT_DOMAIN}.key")
    web_cert_crt_path = os.path.join(SERVER_PUBLIC_DIR, f"{VAULT_NAME}{VAULT_DOMAIN}.crt")
    if not os.path.exists(web_cert_key_path) or not os.path.exists(web_cert_crt_path):
        ip = get_system_ip()
        create_certificate(VAULT_NAME,ip_address=ip, is_server=True, validity_days=398)

# New certificate for vault web server creation
def create_certificate(hostname, ip_address=None, is_server=False, validity_days=398, root_ca=False):
    now = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
    client_name = hostname + VAULT_DOMAIN
    if root_ca:
        private_key_path = os.path.join(ROOT_CA_PRIVATE_DIR, f"{client_name}.key")
        public_cert_path = os.path.join(ROOT_CA_PUBLIC_DIR, f"{client_name}.crt")
    elif is_server and not root_ca:
        private_key_path = os.path.join(SERVER_PRIVATE_DIR, f"{client_name}.key")
        public_cert_path = os.path.join(SERVER_PUBLIC_DIR, f"{client_name}.crt")
    else:
        private_key_path = os.path.join(CERTS_PRIVATE_DIR, f"{client_name}.key")
        public_cert_path = os.path.join(CERTS_PUBLIC_DIR, f"{client_name}.crt")

    if os.path.exists(private_key_path) or os.path.exists(public_cert_path):
        return private_key_path, public_cert_path

    subject = f"/C={ssl_template['C']}/ST={ssl_template['ST']}/L={ssl_template['L']}/O={ssl_template['O']}/OU={ssl_template['OU']}/CN={client_name}"

    # Private key generation command
    openssl_gen_key_cmd = [
        "openssl", "genrsa", "-out", private_key_path, "2048"
    ]
    try:
        subprocess.run(openssl_gen_key_cmd, check=True)
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"Error generating private key: {e}")

    # Command for root CA
    if root_ca:
        openssl_gen_cert_cmd = [
            "openssl", "req", "-x509", "-new", "-nodes", "-key", private_key_path,
            "-sha256", "-days", str(validity_days), "-out", public_cert_path,
            "-subj", subject,
            "-addext", "basicConstraints=CA:TRUE,pathlen:0",
            "-addext", "keyUsage=keyCertSign,cRLSign",
            "-addext", "subjectKeyIdentifier=hash",
            "-addext", "authorityKeyIdentifier=keyid:always"
        ]
        try:
            subprocess.run(openssl_gen_cert_cmd, check=True)
        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"Error generating root CA certificate: {e}")
    else:
        # CSR Creation
        csr_path = os.path.join(CSR_DIR, f"{client_name}.csr") if is_server else os.path.join(CSR_DIR, f"{client_name}.csr")
        openssl_gen_csr_cmd = [
            "openssl", "req", "-new", "-sha256", "-key", private_key_path,
            "-subj", subject, "-out", csr_path, "-extensions", "v3_req",
            "-addext", f"subjectAltName=DNS.0:{client_name}, DNS.1:{hostname}"
        ]
        # If ip address was sent, append it to alternative name.
        if ip_address:
            openssl_gen_csr_cmd[-1] += f",IP.0:{ip_address}"
        try:
            subprocess.run(openssl_gen_csr_cmd, check=True)
        except subprocess.CalledProcessError as e:
            logging.error(f"Error generating CSR: {e}")
            raise RuntimeError(f"Error generating CSR: {e}")

        # Uses root CA to create new certs
        root_ca_key_path = os.path.join(ROOT_CA_PRIVATE_DIR, f"{VAULT_NAME}{VAULT_DOMAIN}.key")
        root_ca_cert_path = os.path.join(ROOT_CA_PUBLIC_DIR, f"{VAULT_NAME}{VAULT_DOMAIN}.crt")
        if ip_address:
            openssl_sign_cert_cmd = [
                "openssl", "x509", "-req", "-in", csr_path, "-CA", root_ca_cert_path,
                "-CAkey", root_ca_key_path, "-CAcreateserial",
                "-out", public_cert_path, "-days", str(validity_days), "-sha256",
                "-extfile", f"<(printf \"basicConstraints=CA:FALSE\\nkeyUsage=digitalSignature,keyEncipherment\\nextendedKeyUsage=serverAuth\\nsubjectAltName=DNS.0:{client_name}, DNS.1:{hostname},IP.0:{ip_address}\")"
            ]
        else:
            openssl_sign_cert_cmd = [
                "openssl", "x509", "-req", "-in", csr_path, "-CA", root_ca_cert_path,
                "-CAkey", root_ca_key_path, "-CAcreateserial",
                "-out", public_cert_path, "-days", str(validity_days), "-sha256",
                "-extfile", f"<(printf \"basicConstraints=CA:FALSE\\nkeyUsage=digitalSignature,keyEncipherment\\nextendedKeyUsage=serverAuth\\nsubjectAltName=DNS.0:{client_name}, DNS.1:{hostname}\")"
            ]

        try:
            subprocess.run(" ".join(openssl_sign_cert_cmd), check=True, shell=True, executable="/bin/bash")
        except subprocess.CalledProcessError as e:
            logging.error(f"Error signing certificate with root CA: {e}")
            raise RuntimeError(f"Error signing certificate with root CA: {e}")

    return private_key_path, public_cert_path

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

    logging.info(f"Keys generated for client {client_id} and saved in {os.path.join(BASE_DIR, str(client_id))}")

#api_key sha512 hash generation:
def generateHash(apikey, salt_len=8, iterations=65000):
    result = passlib.hash.sha512_crypt.using(salt=secrets.token_hex(salt_len), rounds=iterations).hash(apikey)
    return result

#api_key validation:
def hashvalidation(hash, apikey):
    verifica = passlib.hash.sha512_crypt.verify(apikey, hash)
    return verifica


def errorpage():
    page = """
    <!doctype html>
    <html lang=en>
    <title>404 Not Found</title>
    <h1>Not Found</h1>
    <p>The requested URL was not found on the server. If you entered the URL manually please check your spelling and try again.</p>
    """
    return page
# Helper: Connect to database
def get_db_connection():
    return mysql.connector.connect(**DB_CONFIG)

# Helper: Validate inputs
def validate_input(input_str):
    if not input_str or not re.match(r"^[a-zA-Z0-9-_ ]+$", input_str):
        return False
    return True

# Helper: Authenticate client
def authenticate(api_id, api_key):
    connection = get_db_connection()
    cursor = connection.cursor()

    try:
        cursor.execute("SELECT id_cli_int, key_api_vch, lvl_api_int FROM apis WHERE id_api_vch = %s", (api_id,))
        client = cursor.fetchone()

        if not client:
            return None

        client_id, hashed_api_key, api_level = client

        # validate hashedkey
        if hashvalidation(hashed_api_key, api_key):
            return client_id, api_level
        return None
    finally:
        cursor.close()
        connection.close()

# Helper: Check permissions
def check_permissions(api_level, required_level):
    if api_level >= required_level:
        return True
    elif api_level < required_level:
        return False
    else:
        return False
# Function: Generate new keys
def generate_new_keys(client_dir):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    private_key_path = os.path.join(client_dir, "private_key.pem")
    public_key_path = os.path.join(client_dir, "public_key.pem")

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

    return private_key, public_key

# Reject any conection without SSL
@app.before_request
@limiter.limit(LIMITER_CONFIG) 
def enforce_https():
    if not request.is_secure:
        return jsonify({"error": "Insecure connection. Use HTTPS."}), 403

# Test Endpoint to validate API operation
@app.route('/api/test', methods=['GET', 'POST'])
@limiter.limit(LIMITER_CONFIG) 
def test():
    return jsonify({"status":"success", "Test": "OK"}), 200

# Endpoint: Delete client
@app.route('/api/client_del', methods=['POST'])
@limiter.limit(LIMITER_CONFIG) 
def client_del():
    data = request.json
    ip_address=get_client_ip()
    if len(data[0]) != 3:
        logging.warning(f"Warning: Endpoint: /api/client_del, The parameter quantity is incorrect. Source: {ip_address}")
        return jsonify({"error": "The parameter quantity is incorrect."}), 400
    api_id = data.get('api_id')
    api_key = data.get('api_key')
    client_name = data.get('client_name')
    if not is_valid_input(api_id,max_length=17) or not is_valid_input(api_key,max_length=36) or not is_valid_input(client_name,max_length=45):
        logging.warning(f"Warning: Endpoint: /api/client_del, Invalid parameter input validation. Source: {ip_address}")
        return jsonify({"error": "Invalid input."}), 400

    if not all(map(validate_input, [api_id, api_key, client_name, param_name])):
        logging.warning(f"Warning: Endpoint: /api/client_del, Invalid Input. Source: {ip_address}")
        return jsonify({"error": "Invalid input."}), 400

    auth_result = authenticate(api_id, api_key)
    if auth_result is None:
        logging.warning(f"Warning: Endpoint: /api/client_del, Invalid authentication for {api_id}. Source: {ip_address}")
        return jsonify({"error": "Auth Error!"}), 403

    client_id, api_level = auth_result

    connection = get_db_connection()
    cursor = connection.cursor()
    try:
        if api_level < 3:
            logging.error(f"Error: Required level not met when trying to delete client. Endpoint: /api/client_del, Source: {ip_address}")
            return jsonify({"error": "Required leve not met."})
        # Retrieve client ID
        cursor.execute("SELECT id_cli_int FROM clients WHERE nom_cli_vch = %s", (client_name,))
        client = cursor.fetchone()


        if not client:
            logging.warning(f"Warning: Endpoint: /api/client_del, Invalid client name: {client_name} for {api_id}. Source: {ip_address}")
            return errorpage(), 404

        del_client_id = client[0]
        cursor.execute("DELETE FROM params WHERE id_cli_int = %s",(del_client_id,))
        cursor.execute("DELETE FROM apis WHERE id_cli_int = %s",(del_client_id,))
        cursor.execute("DELETE FROM clients WHERE id_cli_int = %s",(del_client_id,))
        
        logging.info(f"status: Success, Endpoint: /api/client_del, Client, APIs and Params deleted: {client_name} for: {api_id}, Source: {ip_address}")
        return jsonify(({"status": "success", "value": "Params, APIs, Client deleted"}))
    finally:
        cursor.close()
        connection.close()

# Endpoint: Read a parameter
@app.route('/api/read_param', methods=['POST'])
@limiter.limit(LIMITER_CONFIG) 
def read_param():
    data = request.json
    ip_address=get_client_ip()
    if len(data[0]) != 4:
        logging.warning(f"Warning: Endpoint: /api/read_params, The parameter quantity is incorrect. Source: {ip_address}")
        return jsonify({"error": "The parameter quantity is incorrect."}), 400
    api_id = data.get('api_id')
    api_key = data.get('api_key')
    client_name = data.get('client_name')
    param_name = data.get('param_name')
    if not is_valid_input(api_id,max_length=17) or not is_valid_input(api_key,max_length=36) or not is_valid_input(client_name,max_length=45) or not is_valid_input(param_name, pattern="^[a-zA-Z0-9][a-zA-Z0-9._-]{0,100}$", max_length=100):
        logging.warning(f"Warning: Endpoint: /api/read_params, Invalid parameter input validation. Source: {ip_address}")
        return jsonify({"error": "Invalid input."}), 400

    if not all(map(validate_input, [api_id, api_key, client_name, param_name])):
        logging.warning(f"Warning: Endpoint: /api/read_params, Invalid Input. Source: {ip_address}")
        return jsonify({"error": "Invalid input."}), 400

    auth_result = authenticate(api_id, api_key)
    if auth_result is None:
        logging.warning(f"Warning: Endpoint: /api/read_params, Invalid authentication for {api_id}. Source: {ip_address}")
        return jsonify({"error": "Auth Error!"}), 403

    client_id, api_level = auth_result

    connection = get_db_connection()
    cursor = connection.cursor()

    try:
        # Retrieve client ID
        cursor.execute("SELECT id_cli_int FROM clients WHERE nom_cli_vch = %s", (client_name,))
        client = cursor.fetchone()

        if not client:
            logging.warning(f"Warning: Endpoint: /api/read_params, Invalid client name: {client_name} for {api_id}. Source: {ip_address}")
            return errorpage(), 404

        client_id = client[0]

        # Retrieve the parameter
        cursor.execute("SELECT val_par_vch FROM params WHERE id_cli_int = %s AND nom_par_vch = %s", (client_id, param_name))
        encrypted_param = cursor.fetchone()

        if not encrypted_param:
            logging.warning(f"Warning: Endpoint: /api/read_params, Invalid parameter: {param_name} for {api_id}. Source: {ip_address}")
            return errorpage(), 404

        encrypted_value = base64.b64decode(encrypted_param[0])

        # Load private key
        private_key_path = os.path.join(BASE_DIR, str(client_id), "private_key.pem")
        with open(private_key_path, "rb") as f:
            private_key = serialization.load_pem_private_key(f.read(), password=None)

        # Decrypt the parameter value
        decrypted_value = private_key.decrypt(
            encrypted_value,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=SHA256()),
                algorithm=SHA256(),
                label=None
            )
        )
        logging.info(f"status: Success, Endpoint: /api/read_params, parameter: {param_name} for: {api_id}, Source: {ip_address}")
        return jsonify(({"status": "success", "parameter":param_name, "value": decrypted_value.decode()}))
    finally:
        cursor.close()
        connection.close()

# Endpoint: Count duplicated parameters
@app.route('/api/count_params', methods=['POST'])
@limiter.limit(LIMITER_CONFIG) 
def count_params():
    data = request.json
    ip_address=get_client_ip()
    if len(data[0]) != 4:
        logging.warning(f"Warning: Endpoint: /api/count_params, The parameter quantity is incorrect. Source: {ip_address}")
        return jsonify({"error": "The parameter quantity is incorrect."}), 400
    api_id = data.get('api_id')
    api_key = data.get('api_key')
    client_name = data.get('client_name')
    param_name = data.get('param_name')
    if not is_valid_input(api_id,max_length=17) or not is_valid_input(api_key,max_length=36) or not is_valid_input(client_name,max_length=45) or not is_valid_input(param_name, pattern="^[a-zA-Z0-9][a-zA-Z0-9._-]{0,100}$", max_length=100):
        logging.warning(f"Warning: Endpoint: /api/count_params, Invalid parameter input validation. Source: {ip_address}")
        return jsonify({"error": "Invalid input."}), 400

    if not all(map(validate_input, [api_id, api_key, client_name, param_name])):
        logging.warning(f"Warning: Endpoint: /api/count_params, Incorrect parameters. Source: {ip_address}")
        return jsonify({"error": "Invalid input."}), 400

    auth_result = authenticate(api_id, api_key)
    if auth_result is None:
        logging.warning(f"Warning: Endpoint: /api/count_params, Invalid authentication. Source: {ip_address}")
        return jsonify({"error": "Error de autenticacion!"}), 403

    client_id, api_level = auth_result

    connection = get_db_connection()
    cursor = connection.cursor()

    try:
        # Retrieve client ID
        cursor.execute("SELECT id_cli_int,nom_cli_vch FROM clients WHERE nom_cli_vch = %s", (client_name,))
        client = cursor.fetchone()
        if (not client) or (api_level < 3 and client[1] != client_name):
            logging.warning(f"Warning: Endpoint: /api/count_params, Below minimum level for {client_name}. Source: {ip_address}")
            return jsonify({"error": "Below minimum level!"}), 404
        elif (api_level < 1 and client[1] == client_name):
            logging.warning(f"Warning: Endpoint: /api/count_params, Below minimum level for {client_name}. Source: {ip_address}")
            return jsonify({"error": "Below minimum level!"}), 404
        
        client_id = client[0]

        # Count duplicated parameters
        cursor.execute("SELECT COUNT(*) FROM params WHERE id_cli_int = %s AND nom_par_vch = %s", (client_id, param_name))
        count = cursor.fetchone()
        logging.info(f"status: success, parameter: {param_name}, count: {count}")
        return jsonify({"status":"success", "parameter": param_name, "count": count}), 200
    finally:
        cursor.close()
        connection.close()

# Endpoint: Regenerate certificate
@app.route('/api/regenerate_cert', methods=['POST'])
@limiter.limit(LIMITER_CONFIG) 
def regenerate_cert():
    data = request.json
    ip_address = get_client_ip()
    if len(data[0]) != 3:
        logging.warning(f"Warning: Endpoint: /api/regenerate_cert, The parameter quantity is incorrect. Source: {ip_address}")
        return jsonify({"error": "The parameter quantity is incorrect."}), 400 
    api_id = data.get('api_id')
    api_key = data.get('api_key')
    client_name = data.get('client_name')
    if not is_valid_input(api_id,max_length=17) or not is_valid_input(api_key,max_length=36) or not is_valid_input(client_name,max_length=45):
        logging.warning(f"Warning: Endpoint: /api/regenerate_cert, Invalid parameter input validation. Source: {ip_address}")
        return jsonify({"error": "Invalid input."}), 400

    if not all(map(validate_input, [api_id, api_key, client_name])):
        logging.warning(f"Warning: Endpoint: /api/regenerate_cert, Incorrect parameters. Source: {ip_address}")
        return jsonify({"error": "Invalid input."}), 400

    auth_result = authenticate(api_id, api_key)
    if auth_result is None:
        logging.warning(f"Warning: Endpoint: /api/regenerate_cert, Invalid authentication. Source: {ip_address}")
        return jsonify({"error": "Authentication error"}), 403

    client_id, api_level = auth_result

    if not check_permissions(api_level, 3):
        return jsonify({"error": "Insufficient permissions."}), 403

    connection = get_db_connection()
    cursor = connection.cursor()

    try:
        # Retrieve client ID
        cursor.execute("SELECT id_cli_int FROM clients WHERE nom_cli_vch = %s", (client_name,))
        client = cursor.fetchone()

        if not client:
            logging.error(f"error: Client {client_name} doesn't exist. From source: {ip_address}")
            return jsonify({"error": "Client doesn't exist."}), 404

        client_id = client[0]
        client_dir = os.path.join(BASE_DIR, str(client_id))

        # Backup old certificate, if changed again, backup will be lost. Backup is used to change param cypher to new keys.
        private_key_path = os.path.join(client_dir, "private_key.pem")
        public_key_path = os.path.join(client_dir, "public_key.pem")
        os.rename(private_key_path, private_key_path + ".bkp")
        os.rename(public_key_path, public_key_path + ".bkp")

        # Generate new keys
        private_key, public_key = generate_new_keys(client_dir)

        # Update all encrypted data
        cursor.execute("SELECT id_par_int, val_par_vch FROM params WHERE id_cli_int = %s", (client_id,))
        parameters = cursor.fetchall()

        for param_id, encrypted_value in parameters:
            old_value = base64.b64decode(encrypted_value)
            decrypted_value = private_key.decrypt(
                old_value,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=SHA256()),
                    algorithm=SHA256(),
                    label=None
                )
            )

            new_encrypted_value = public_key.encrypt(
                decrypted_value,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=SHA256()),
                    algorithm=SHA256(),
                    label=None
                )
            )
            cursor.execute(
                "UPDATE params SET val_par_vch = %s WHERE id_par_int = %s",
                (base64.b64encode(new_encrypted_value).decode(), param_id)
            )

        connection.commit()

        # Remove old certificate backup
        os.remove(private_key_path + ".bkp")
        os.remove(public_key_path + ".bkp")
        logging.info(f"status: success, message: Certificate regenerated successfully for client {client_name}. From : {ip_address}")
        return jsonify({"status": "success","message": "Certificate regenerated successfully."}), 200
    finally:
        cursor.close()
        connection.close()

# Endpoint: Client add 
@app.route('/api/client_add', methods=['POST'])
@limiter.limit(LIMITER_CONFIG) 
def client_add():
    data = request.json
    ip_address = get_client_ip()

    if len(data[0]) != 4:
        logging.warning(f"Warning: Endpoint: /api/client_add, The parameter quantity is incorrect. Source: {ip_address}")
        return jsonify({"error": "The parameter quantity is incorrect."}), 400

    api_id = data.get('api_id')
    api_key = data.get('api_key')
    client_name = data.get('client_name')
    level = data.get('client_level')

    if not is_valid_input(api_id,max_length=17) or not is_valid_input(api_key,max_length=36) or not is_valid_input(client_name,max_length=45) or not is_valid_input(level, pattern="^[0-9]{1,1}$", max_length=1):
        logging.warning(f"Warning: Endpoint: /api/client_add, Invalid parameter input validation. Source: {ip_address}")
        return jsonify({"error": "Invalid input."}), 400

    auth_result = authenticate(api_id, api_key)
    if auth_result is None:
        logging.warning(f"Warning: Endpoint: /api/client_add, Invalid authentication. Source: {ip_address}")
        return jsonify({"error": "Authentication Error"}), 403
    client_id, api_level = auth_result
    if not check_permissions(api_level, 3):
        return jsonify({"error": "Insuficient permissions."}), 403
    # Connect to DB
    connection = get_db_connection()
    cursor = connection.cursor()

    try:
        # Check if client already exists
        cursor.execute("SELECT id_cli_int FROM clients WHERE nom_cli_vch = %s", (client_name,))
        existing_client = cursor.fetchone()

        if existing_client:
            logging.info(f"Warning: Trying to add invalid client: /api/client_add, Client already used. Client: {client_name}, Source: {ip_address}")
            return jsonify({"error": "Client Exists"}), 403
        # Insert client into DB.
        cursor.execute("INSERT INTO clients (nom_cli_vch, lvl_cli_int) VALUES (%s, %s)", (client_name,level,))
        connection.commit()
        client_id = cursor.lastrowid

        # Create directory using client ID
        client_dir = os.path.join(BASE_DIR, str(client_id))
        create_directory(client_dir)
        # Generate API keys id 8-8, key 4-8-4-8-8
        api_id = ''.join(random.choices(string.ascii_letters + string.digits, k=8) + list('-') + random.choices(string.ascii_letters + string.digits, k=8))
        api_key = ''.join(random.choices(string.ascii_letters + string.digits, k=4) + list('-') + random.choices(string.ascii_letters + string.digits, k=8) + list('-') + random.choices(string.ascii_letters + string.digits, k=4) + list('-') + random.choices(string.ascii_letters + string.digits, k=8) + list('-') + random.choices(string.ascii_letters + string.digits, k=8))

        # Generate SSL keys
        generate_ssl(client_id)

        # API HASH
        hashedkey = generateHash(api_key)
        
        # Insert into apis table
        cursor.execute(
            "INSERT INTO apis (id_api_vch, key_api_vch, id_cli_int) VALUES (%s, %s, %s)",
            (api_id, hashedkey, str(client_id))
        )
        connection.commit()
        logging.info(f"status: success, message: Client added., Client: {client_name}, API_ID: str({api_id})")
        return jsonify({"status": "success","mensaje": "Client added.", "Client": client_name, "API_ID": api_id, "API_KEY": api_key}), 200
    finally:
        cursor.close()
        connection.close()

# Security Headers: 
# X-Frame-Options: Prevent Clickjacking and frames in this site.
# X-XSS-Protection: protect against Cross Site Scripting attacks.
# HSTS force only https conection to this site.
# X-Content-Type-Options: Prevent MIME Sniff in sites, even when this server uses json, python clients will have no problems.
@app.after_request
def set_security_headers(response):
    response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response

# Main Function
if __name__ == '__main__':
    configure_logging()
    ensure_directories()
    # Validate server certificate before start
    validate_server_certificate()
    # Validate directory permissions
    set_secure_permissions(VAULT_BASE_DIR)
    # Use HTTPS Certificates
    web_cert_key_path = os.path.join(SERVER_PRIVATE_DIR, f"{VAULT_NAME}{VAULT_DOMAIN}.key")
    web_cert_crt_path = os.path.join(SERVER_PUBLIC_DIR, f"{VAULT_NAME}{VAULT_DOMAIN}.crt")

    print(f"System IP: {local_ip}")

   # To Do: Use Nginx as load balancer and reverse proxy adding mod_security for aditional regexp protection and variables validation.

    options = {
        "bind": "0.0.0.0:11443",
        "workers": "4", # Gunicorn workers, addjust as you need.
        "certfile": web_cert_crt_path,
        "keyfile": web_cert_key_path,
        "ssl-version": "TLSv1_2"
    }

    GunicornApp(app, options).run()
