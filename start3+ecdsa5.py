import hashlib
import secrets
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from ecdsa import SigningKey, SECP256k1
import os

# Configuración
NUM_THREADS = 4  # Ajusta según la máquina, generalmente entre 4-8 para mejor rendimiento
PATTERN = "deadbeef"  # Patrón en hexadecimal
RANGE_LIMIT = 1000000  # Rango para valores cercanos
KNOWN_KEY = int("1deadbeef123456789abcdef0fedcba987654321", 16)
BATCH_SIZE = 100  # Número de claves a procesar por lote
MATCH_LIMIT = 100  # Límite de coincidencias antes de escribir en el archivo
OUTPUT_FILE = "matches.txt"  # Archivo de salida
WALLET_FILE = "wallet.json"  # Archivo JSON de la wallet para verificar la clave

# Contadores globales
hashes_verified = 0
match_buffer = []

# Lock para manejo seguro de recursos compartidos
lock = threading.Lock()

# Función para cargar direcciones o hashes desde un archivo
def load_hashes_from_file(filename):
    hashes = set()
    try:
        with open(filename, 'r', encoding='utf-8') as file:
            for line in file:
                address = line.strip().lower()
                if address:
                    hashes.add(address)
        print(f"Se cargaron {len(hashes)} direcciones/hashes desde {filename}.")
    except FileNotFoundError:
        print(f"El archivo {filename} no se encontró. Asegúrate de que exista.")
    return hashes

# Función optimizada para generar claves privadas con patrones
def generate_private_key(pattern=None, base_key=None, offset=0):
    if pattern:
        secret_hex = f"{pattern}{secrets.token_hex(28)}"
    elif base_key is not None:
        # Generamos un offset dinámico para mayor variabilidad
        secret_hex = f"{base_key + offset + secrets.randbelow(10000):064x}"
    else:
        secret_hex = secrets.token_hex(32)
    return int(secret_hex, 16)

# Función para convertir clave privada a dirección Ethereum
def private_key_to_eth_address(private_key):
    sk = SigningKey.from_secret_exponent(private_key, curve=SECP256k1)
    vk = sk.verifying_key
    public_key = b"\x04" + vk.to_string()  # Prefijo para clave pública no comprimida
    keccak_hash = hashlib.new("sha3_256", public_key[1:]).digest()
    eth_address = "0x" + keccak_hash[-20:].hex()
    return eth_address

# Función para procesar un lote de claves
def process_batch(batch_size, address_hashes, pattern=None, base_key=None):
    global hashes_verified
    local_count = 0
    local_matches = []

    for _ in range(batch_size):
        secret_exponent = generate_private_key(pattern, base_key, _)
        private_key_hex = f"{secret_exponent:064x}"
        eth_address = private_key_to_eth_address(secret_exponent)

        if eth_address in address_hashes:
            local_matches.append(f"Dirección: {eth_address}\nClave privada: {private_key_hex}\n{'=' * 55}\n")

        local_count += 1

    # Actualizar el contador global de hashes verificados
    with lock:
        hashes_verified += local_count

    # Almacenar coincidencias en el búfer
    with lock:
        match_buffer.extend(local_matches)

# Función para escribir las coincidencias en el archivo en lotes
def write_matches_to_file():
    global match_buffer
    while True:
        time.sleep(5)  # Verifica y escribe las coincidencias cada 5 segundos
        with lock:
            if len(match_buffer) >= MATCH_LIMIT:  # Solo escribir si alcanzamos el límite de coincidencias
                with open(OUTPUT_FILE, "a") as f:
                    f.writelines(match_buffer)
                match_buffer.clear()

# Función para mostrar estadísticas cada 15 segundos
def display_statistics():
    global hashes_verified
    while True:
        time.sleep(15)
        with lock:
            print(f"Hashes verificados en los últimos 15 segundos: {hashes_verified}")
            hashes_verified = 0

# Búsqueda infinita con patrones y concurrencia
def infinite_search_with_patterns(address_hashes):
    # Iniciar hilo para mostrar estadísticas
    stats_thread = threading.Thread(target=display_statistics, daemon=True)
    stats_thread.start()

    # Iniciar hilo para escribir las coincidencias en el archivo
    write_thread = threading.Thread(target=write_matches_to_file, daemon=True)
    write_thread.start()

    # Procesar claves con concurrencia
    with ThreadPoolExecutor(max_workers=NUM_THREADS) as executor:
        while True:
            futures = [
                executor.submit(process_batch, BATCH_SIZE, address_hashes, PATTERN, KNOWN_KEY)
                for _ in range(NUM_THREADS)
            ]
            for future in futures:
                future.result()

# Función para intentar abrir un archivo JSON de wallet y verificar su contenido
def tryopen_wallet(filename):
    try:
        with open(filename, 'r') as file:
            wallet_data = json.load(file)
        print(f"Wallet cargada correctamente desde {filename}.")
        return wallet_data
    except Exception as e:
        print(f"Error al cargar el archivo de la wallet: {e}")
        return None

# Función para validar si una clave privada corresponde a la dirección de la wallet
def validate_wallet_key(private_key, wallet_data):
    eth_address = private_key_to_eth_address(private_key)
    if eth_address == wallet_data.get('ethaddr'):
        print(f"Coincidencia encontrada! Dirección Ethereum: {eth_address}")
        return True
    return False

if __name__ == "__main__":
    print("Iniciando búsqueda con patrones...")

    # Cargar hashes desde archivo
    filename = "eth.txt"  # Cambia esto por la ruta de tu archivo de direcciones
    loaded_hashes = load_hashes_from_file(filename)

    # Cargar la wallet desde archivo para verificar las claves
    wallet_data = tryopen_wallet(WALLET_FILE)

    if wallet_data is None:
        print("No se pudo cargar la wallet, pero continuaré con la búsqueda.")
    
    # Iniciar la búsqueda
    infinite_search_with_patterns(loaded_hashes)
