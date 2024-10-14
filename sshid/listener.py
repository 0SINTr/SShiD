#!/usr/bin/env python3
"""
Listener Script for SShiD

This script listens for beacon frames with a specific SSID and extracts
an encrypted message from the Vendor-Specific Information Element.
It then decrypts and displays the message to the user.

Requirements:
- Python 3
- scapy
- cryptography
- root privileges to sniff raw packets

Usage:
sudo python3 listener.py
"""

import os
import sys
import base64
import hashlib
import subprocess
from getpass import getpass
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from scapy.all import sniff, Dot11, Dot11Beacon, Dot11Elt
from scapy.layers.dot11 import Dot11EltVendorSpecific
import logging

logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')

def derive_key(password, salt, iterations=100000):
    """
    Derives a cryptographic key from a password using PBKDF2HMAC.

    Args:
        password (str): The password provided by the user.
        salt (bytes): A unique salt value for key derivation.
        iterations (int): The number of iterations for the KDF (default: 100,000).

    Returns:
        bytes: A 256-bit (32-byte) key derived from the password.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # 256 bits
        salt=salt,
        iterations=iterations,
    )
    key = kdf.derive(password.encode())
    return key

def generate_ssid_identifier(password):
    """
    Generates an SSID identifier by hashing the password and encoding it.

    Args:
        password (str): The secret password provided by the user.

    Returns:
        str: A Base64 URL-safe encoded string used as the SSID.
    """
    # Use a fixed salt for the SSID hash to ensure both parties generate the same SSID
    ssid_salt = b'sshid_ssid_salt'
    ssid_hash = hashlib.sha256(password.encode() + ssid_salt).digest()
    # Use Base64 URL-safe encoding and truncate to 32 characters
    ssid = base64.urlsafe_b64encode(ssid_hash).decode('utf-8').rstrip('=')[:32]
    return ssid

def decrypt_message(nonce, ciphertext, key):
    """
    Decrypts a ciphertext using ChaCha20-Poly1305.

    Args:
        nonce (bytes): The nonce used during encryption.
        ciphertext (bytes): The encrypted message.
        key (bytes): The encryption key derived from the password.

    Returns:
        str: The decrypted plaintext message.
    """
    aead = ChaCha20Poly1305(key)
    plaintext = aead.decrypt(nonce, ciphertext, None)
    return plaintext.decode('utf-8')

def decode_data(encoded_data):
    """
    Decodes a Base64 URL-safe string back into the nonce and ciphertext.

    Args:
        encoded_data (str): The encoded string containing the nonce and ciphertext.

    Returns:
        tuple: A tuple containing the nonce (bytes) and ciphertext (bytes).
    """
    # Add padding if necessary
    padding_needed = (4 - len(encoded_data) % 4) % 4
    encoded_data += '=' * padding_needed
    data = base64.urlsafe_b64decode(encoded_data)
    nonce = data[:12]  # First 12 bytes are the nonce
    ciphertext = data[12:]
    return nonce, ciphertext

def get_wireless_interface():
    """
    Detects and returns the name of the wireless interface.

    Returns:
        str: The name of the wireless interface to use.

    Raises:
        SystemExit: If no wireless interfaces are found or an invalid selection is made.
    """
    try:
        result = subprocess.run(['iw', 'dev'], capture_output=True, text=True)
        lines = result.stdout.splitlines()
        interfaces = [line.strip().split(' ')[1] for line in lines if 'Interface' in line]
        if not interfaces:
            logging.error('No wireless interfaces found.')
            sys.exit(1)
        elif len(interfaces) == 1:
            return interfaces[0]
        else:
            logging.info('Multiple wireless interfaces detected:')
            for idx, iface in enumerate(interfaces):
                logging.info(f'{idx + 1}: {iface}')
            choice = int(input('Select interface [1-{}]: '.format(len(interfaces))))
            if 1 <= choice <= len(interfaces):
                return interfaces[choice - 1]
            else:
                logging.error('Invalid selection.')
                sys.exit(1)
    except Exception as e:
        logging.error(f'Error detecting wireless interface: {e}')
        sys.exit(1)

def process_packet(packet, target_ssid, key):
    """
    Processes captured packets, looking for the target SSID and decrypting the message.

    Args:
        packet (scapy.packet.Packet): The captured packet to process.
        target_ssid (str): The SSID to match against.
        key (bytes): The decryption key derived from the password.
    """
    if packet.haslayer(Dot11Beacon):
        # Extract the SSID
        ssid = packet[Dot11Elt].info.decode('utf-8', errors='ignore')
        if ssid == target_ssid:
            logging.info(f'Detected target SSID: {ssid}')
            # Look for Vendor-Specific IE
            vendor_ies = [ie for ie in packet[Dot11Elt] if ie.ID == 221]
            for ie in vendor_ies:
                try:
                    # Extract the encrypted data
                    encoded_data = ie.info.decode('utf-8', errors='ignore')
                    # Decode and decrypt the message
                    nonce, ciphertext = decode_data(encoded_data)
                    message = decrypt_message(nonce, ciphertext, key)
                    logging.info(f'Received message: {message}')
                    input('Press Enter to continue listening.')
                except Exception as e:
                    logging.error(f'Error decrypting message: {e}')

def listener_main():
    """
    Main function for the Listener script.

    - Obtains the wireless interface.
    - Prompts the user for the secret password.
    - Generates the SSID and decryption key.
    - Sets the interface to monitor mode on the specified channel.
    - Starts sniffing for beacon frames with the matching SSID.
    - Processes incoming beacon frames and decrypts the message.
    """
    iface = get_wireless_interface()
    password = getpass('Enter secret password: ')
    ssid = generate_ssid_identifier(password)
    logging.info(f'SSID to search for: {ssid}')

    # Derive decryption key
    encryption_salt = b'sshid_encryption_salt'
    key = derive_key(password, encryption_salt)

    # Specify the channel (e.g., 6)
    channel = 6

    # Start sniffing beacon frames
    logging.info(f'Listening for beacon frames on channel {channel}.')
    sniff(prn=lambda pkt: process_packet(pkt, ssid, key), iface=iface, store=0)

if __name__ == '__main__':
    listener_main()
