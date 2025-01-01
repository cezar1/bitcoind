#!/usr/bin/env python3
# Copyright (c) 2015-2021 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

from argparse import ArgumentParser
from getpass import getpass
from secrets import token_hex, token_urlsafe
import hmac
import json

def generate_salt(size):
    """Create size byte hex salt"""
    return token_hex(size)

def generate_password():
    """Create 32 byte b64 password"""
    return token_urlsafe(32)

def password_to_hmac(salt, password):
    m = hmac.new(salt.encode('utf-8'), password.encode('utf-8'), 'SHA256')
    return m.hexdigest()

def main():
    parser = ArgumentParser(description='Create login credentials for a JSON-RPC user')
    parser.add_argument('username', help='the username for authentication')
    parser.add_argument('password', help='leave empty to generate a random password or specify "-" to prompt for password', nargs='?')
    args = parser.parse_args()

    if not args.password:
        args.password = generate_password()
    elif args.password == '-':
        args.password = getpass()

    # Create 16 byte hex salt
    salt = generate_salt(16)
    password_hmac = password_to_hmac(salt, args.password)
    
    # Write output to multiple files
    base_filename = 'bitcoin_rpc_auth'
    
    # Original rpcauth format
    with open(f'{base_filename}.conf', 'w') as f:
        f.write(f'rpcauth={args.username}:{salt}${password_hmac}\n')
    
    # JSON format
    with open(f'{base_filename}.json', 'w') as f:
        odict={'username':args.username, 'password':args.password, 'rpcauth':f'{args.username}:{salt}${password_hmac}'}
        f.write(json.dumps(odict))
    
    # Bitcoin Core credentials format
    with open(f'{base_filename}_credentials.conf', 'w') as f:
        f.write(f'rpcuser={args.username}\n')
        f.write(f'rpcpassword={args.password}\n')
    
    print(
        'Credential files in various formats have been output to git ignored files:\n'
        '- bitcoin_rpc_auth.conf\n'
        '- bitcoin_rpc_auth.json\n'
        '- bitcoin_rpc_auth_credentials.conf\n'
        'in repo root'
    )

if __name__ == '__main__':
    main()