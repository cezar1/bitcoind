#!/usr/bin/env python3

import json
import binascii
import struct
import sys
import hashlib
import base58
import bech32
from datetime import datetime

def hash160(data):
    """Perform the RIPEMD-160(SHA-256(data)) hash"""
    return hashlib.new('ripemd160', hashlib.sha256(data).digest()).digest()

def p2pkh_to_address(script_hex):
    """Convert a P2PKH script to a Bitcoin address"""
    # P2PKH format: OP_DUP OP_HASH160 <pubKeyHash> OP_EQUALVERIFY OP_CHECKSIG
    # Typical format: 76a914<20-byte-hash>88ac
    if len(script_hex) == 50 and script_hex.startswith("76a914") and script_hex.endswith("88ac"):
        pubkey_hash = bytes.fromhex(script_hex[6:46])
        # Add version byte (0x00 for mainnet)
        versioned_payload = b"\x00" + pubkey_hash
        # Calculate checksum
        checksum = hashlib.sha256(hashlib.sha256(versioned_payload).digest()).digest()[:4]
        # Combine and encode with Base58
        return base58.b58encode(versioned_payload + checksum).decode('utf-8')
    return None

def p2sh_to_address(script_hex):
    """Convert a P2SH script to a Bitcoin address"""
    # P2SH format: OP_HASH160 <scriptHash> OP_EQUAL
    # Typical format: a914<20-byte-hash>87
    if len(script_hex) == 46 and script_hex.startswith("a914") and script_hex.endswith("87"):
        script_hash = bytes.fromhex(script_hex[4:44])
        # Add version byte (0x05 for mainnet)
        versioned_payload = b"\x05" + script_hash
        # Calculate checksum
        checksum = hashlib.sha256(hashlib.sha256(versioned_payload).digest()).digest()[:4]
        # Combine and encode with Base58
        return base58.b58encode(versioned_payload + checksum).decode('utf-8')
    return None

def p2wpkh_to_address(script_hex):
    """Convert a P2WPKH script to a Bech32 address"""
    # P2WPKH format: OP_0 <pubKeyHash>
    # Typical format: 0014<20-byte-hash>
    if len(script_hex) == 44 and script_hex.startswith("0014"):
        pubkey_hash = bytes.fromhex(script_hex[4:])
        # Convert to bech32 address (Segwit v0)
        return bech32.encode("bc", 0, pubkey_hash)
    return None

def decode_coinbase(input_file):
    # Read the file contents
    with open(input_file, 'r') as f:
        raw_log = f.read().strip()

    # Extract the JSON part
    json_start = raw_log.find('{')
    if json_start == -1:
        print("Error: No JSON found in the input file")
        return
    json_str = raw_log[json_start:]

    # Parse the JSON
    try:
        data = json.loads(json_str)
    except json.JSONDecodeError as e:
        print(f"Error parsing JSON: {e}")
        return

    if "method" not in data or data["method"] != "mining.notify" or "params" not in data:
        print("Error: Input is not a valid mining.notify message")
        return

    # Extract the coinbase parts from the mining.notify params
    params = data["params"]
    job_id = params[0]
    prev_block_hash = params[1]
    coinbase_part1 = params[2]
    coinbase_part2 = params[3]
    merkle_branches = params[4]
    version = params[5]
    nbits = params[6]
    ntime = params[7]
    clean_jobs = params[8]

    print("=== Stratum Mining Notification Decoded ===")
    print(f"Job ID: {job_id}")
    print(f"Previous Block Hash: {prev_block_hash}")
    print(f"Version: {version} (Little Endian: {binascii.hexlify(struct.pack('<I', int(version, 16))).decode()})")
    print(f"Difficulty Bits: {nbits}")
    print(f"nTime: {ntime} (Timestamp: {datetime.fromtimestamp(int(ntime, 16))})")
    print(f"Clean Jobs: {clean_jobs}")
    print(f"Merkle Branches: {len(merkle_branches)} branches")

    # Decode the coinbase transaction
    print("\n=== Coinbase Transaction ===")

    # Part 1 is the beginning of the coinbase transaction
    coinbase_hex = coinbase_part1
    print(f"Coinbase Part 1: {coinbase_hex}")

    # Extract version (first 4 bytes)
    version_bytes = coinbase_hex[:8]
    version_int = int(version_bytes, 16)
    print(f"TX Version: {version_int}")

    # Extract input count (should be 1 for coinbase)
    # VarInt is used, but for coinbase it's typically just 01
    input_count = int(coinbase_hex[8:10], 16)
    print(f"Input Count: {input_count}")

    # The coinbase input has a special prevout of all zeros
    prevout_hash = coinbase_hex[10:74]
    prevout_index = coinbase_hex[74:82]
    print(f"Prevout Hash: {prevout_hash}")
    print(f"Prevout Index: {int(prevout_index, 16)}")

    # Extract the coinbase scriptSig length and data
    script_len_hex = coinbase_hex[82:84]
    script_len = int(script_len_hex, 16)
    print(f"ScriptSig Length: {script_len} bytes")

    # Extract the coinbase scriptSig (contains the height and can contain arbitrary data)
    script_sig = coinbase_hex[84:84+script_len*2]
    print(f"ScriptSig: {script_sig}")

    # Try to decode the block height from the scriptSig
    # Bitcoin consensus rules require block height in the coinbase
    # It's encoded after OP_PUSH bytes, the format is typically:
    # OP_PUSH <height in little endian> + optional extra data
    if script_sig.startswith("03"):  # OP_PUSH 3 bytes
        height_bytes = script_sig[2:8]
        height = int.from_bytes(bytes.fromhex(height_bytes), byteorder='little')
        print(f"Block Height: {height}")

    # Part 2 contains the rest of the transaction
    print(f"\nCoinbase Part 2: {coinbase_part2}")

    # Extract the sequence number (4 bytes at the start of part 2)
    sequence = coinbase_part2[:8]
    print(f"Sequence: {sequence}")

    # Extract output count (VarInt) - typically 2 outputs
    # For simplicity we'll assume it's just 1 byte
    output_count = int(coinbase_part2[8:10], 16)
    print(f"Output Count: {output_count}")

    # Start parsing outputs
    offset = 10
    for i in range(output_count):
        # Extract value (8 bytes)
        value_hex = coinbase_part2[offset:offset+16]
        value_satoshis = int.from_bytes(bytes.fromhex(value_hex), byteorder='little')
        value_btc = value_satoshis / 100000000
        print(f"\nOutput #{i+1}")
        print(f"  Value: {value_satoshis} satoshis ({value_btc:.8f} BTC)")
        offset += 16
        
        # Extract script length (VarInt)
        script_len_hex = coinbase_part2[offset:offset+2]
        script_len = int(script_len_hex, 16)
        print(f"  Script Length: {script_len} bytes")
        offset += 2
        
        # Extract script
        script_hex = coinbase_part2[offset:offset+script_len*2]
        offset += script_len*2
        print(f"  Script: {script_hex}")
        
        # Attempt to decode script type and address
        if script_hex.startswith("0014"):
            print(f"  Script Type: P2WPKH (Witness v0 key hash)")
            print(f"  Key Hash: {script_hex[4:]}")
            address = p2wpkh_to_address(script_hex)
            if address:
                print(f"  Address: {address}")
        elif script_hex.startswith("a9") and script_hex.endswith("87"):
            print(f"  Script Type: P2SH (Pay to Script Hash)")
            address = p2sh_to_address(script_hex)
            if address:
                print(f"  Address: {address}")
        elif script_hex.startswith("6a"):
            print(f"  Script Type: OP_RETURN (Null Data)")
            data_hex = script_hex[2:]
            print(f"  Data: {data_hex}")
                           
                
        elif script_hex.startswith("76a914") and script_hex.endswith("88ac"):
            print(f"  Script Type: P2PKH (Pay to Public Key Hash)")
            address = p2pkh_to_address(script_hex)
            if address:
                print(f"  Address: {address}")
        else:
            print(f"  Script Type: Unknown or P2PK")

    # Extract locktime (4 bytes at the end)
    locktime_hex = coinbase_part2[-8:]
    locktime = int(locktime_hex, 16)
    print(f"\nLocktime: {locktime}")

    # Full transaction
    full_tx = coinbase_part1 + coinbase_part2
    print(f"\nFull Transaction Hex: {full_tx}")
    print(f"Transaction ID: {hashlib.sha256(hashlib.sha256(bytes.fromhex(full_tx)).digest()).digest()[::-1].hex()}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <input_file>")
        sys.exit(1)
    
    # Note: This script requires the 'base58' and 'bech32' packages
    # You can install them using pip:
    # pip install base58 bech32
    
    decode_coinbase(sys.argv[1])