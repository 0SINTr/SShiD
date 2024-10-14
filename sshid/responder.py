#!/usr/bin/env python3
# Copyright 2024-2025 © 0SINTr (https://github.com/0SINTr)
from scapy.all import Dot11, Dot11Beacon, Dot11Elt, RadioTap, sendp, sniff
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from colorama import Fore, Style
import subprocess
import base64
import os
import random
import sys

def get_wireless_interface():
    """Detect and select the active wireless interface."""
    try:
        result = subprocess.run(['iw', 'dev'], capture_output=True, text=True)
        lines = result.stdout.splitlines()
        interfaces = [line.split()[1] for line in lines if "Interface" in line]

        if not interfaces:
            print(Style.BRIGHT + "[ERROR] " + Style.RESET_ALL + "No wireless interface found. Exiting.")
            sys.exit(1)

        if len(interfaces) > 1:
            print(Style.BRIGHT + "[INPUT] " + Style.RESET_ALL + "Multiple wireless interfaces detected. Please choose one:")
            for idx, iface in enumerate(interfaces):
                print(f"{idx + 1}. {iface}")
            try:
                choice = int(input(Style.BRIGHT + "[INPUT] " + Style.RESET_ALL + "Enter the number corresponding to your choice: ")) - 1
                if choice < 0 or choice >= len(interfaces):
                    print(Style.BRIGHT + "[ERROR] " + Style.RESET_ALL + "Invalid selection. Exiting.")
                    sys.exit(1)
                selected_interface = interfaces[choice]
            except ValueError:
                print(Style.BRIGHT + "[ERROR] " + Style.RESET_ALL + "Invalid input. Please enter a number.")
                sys.exit(1)
        else:
            selected_interface = interfaces[0]
            print(Style.BRIGHT + "[INFO] " + Style.RESET_ALL + f"Detected wireless interface: {selected_interface}")

        # Check if the interface is UP
        state_check = subprocess.run(['ip', 'link', 'show', selected_interface], capture_output=True, text=True)
        if "state UP" in state_check.stdout:
            return selected_interface
        else:
            print(Style.BRIGHT + "[ERROR] " + Style.RESET_ALL + f"Interface {selected_interface} is DOWN. Please bring it UP before running the script.")
            sys.exit(1)
    except Exception as e:
        print(Style.BRIGHT + "[ERROR] " + Style.RESET_ALL + f"Failed to detect wireless interface: {e}")
        sys.exit(1)

# Function to generate a random MAC address
def random_mac():
    return ':'.join(['%02x' % random.randint(0x00, 0xff) for _ in range(6)])

# Function to derive encryption key from password
def derive_key(password, salt=b'unique_salt', iterations=100000):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # 256-bit key
        salt=salt,
        iterations=iterations,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())
    return key

# Function to encrypt the message
def encrypt_message(message, key):
    # AES-CTR mode with a random nonce
    nonce = os.urandom(16)  # 128-bit nonce
    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(message.encode()) + encryptor.finalize()
    return nonce, ciphertext

# Function to decrypt the message
def decrypt_message(nonce, ciphertext, key):
    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return plaintext.decode()

# Function to generate HMAC identifier
def generate_identifier(key, password, length=4):
    h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
    h.update(password.encode())
    digest = h.finalize()
    identifier = base64.urlsafe_b64encode(digest).decode()[:length]
    return identifier

# Function to construct and send beacon frame
def send_beacon(ssid, iface):
    dot11 = Dot11(type=0, subtype=8, addr1='ff:ff:ff:ff:ff:ff',
                addr2=random_mac(), addr3=random_mac())
    beacon = Dot11Beacon(cap='ESS+privacy')
    essid = Dot11Elt(ID='SSID', info=ssid)
    frame = RadioTap()/dot11/beacon/essid
    sendp(frame, iface=iface, inter=0.1, loop=1, verbose=0)

# Function to encode the message to fit in 28 bytes
def encode_message(nonce, ciphertext):
    # Combine nonce and ciphertext
    data = nonce + ciphertext
    # Base64 encode
    encoded = base64.urlsafe_b64encode(data).decode()
    # Ensure it fits in 28 bytes
    if len(encoded) > 28:
        encoded = encoded[:28]
    else:
        encoded = encoded.ljust(28, '=')
    return encoded

# Function to sniff for incoming messages
def sniff_messages(key, identifier, iface):
    def process_packet(packet):
        if packet.haslayer(Dot11Beacon):
            ssid = packet[Dot11Elt].info.decode(errors='ignore')
            if len(ssid) == 32 and ssid[-4:] == identifier:
                encoded_msg = ssid[:-4]
                try:
                    data = base64.urlsafe_b64decode(encoded_msg + '==')  # Adjust padding
                    nonce = data[:16]
                    ciphertext = data[16:]
                    plaintext = decrypt_message(nonce, ciphertext, key)
                    print(f"\nReceived message from Initiator: {plaintext}")
                    # Ask user for reply
                    reply = input("Enter reply message (max 20 characters): ")
                    if len(reply.encode()) > 21:
                        print("Message too long, truncating to 21 bytes.")
                        reply = reply.encode()[:21].decode()
                    # Encrypt and send reply
                    nonce_reply, ciphertext_reply = encrypt_message(reply, key)
                    encoded_reply = encode_message(nonce_reply, ciphertext_reply)
                    ssid_reply = encoded_reply + identifier
                    print(f"Broadcasting reply SSID: {ssid_reply}")
                    send_beacon(ssid_reply, iface)
                    # Optionally, stop listening after replying
                    sys.exit(0)
                except Exception as e:
                    pass  # Ignore decoding errors
    sniff(iface=iface, prn=process_packet, stop_filter=lambda x: False)

def main():
    iface = input("Enter your wireless interface in monitor mode (e.g., wlan0mon): ")
    password = input("Enter shared password: ")
    key = derive_key(password)
    identifier = generate_identifier(key, password)
    print("Listening for messages...")
    sniff_messages(key, identifier, iface)

if __name__ == "__main__":
    main()
