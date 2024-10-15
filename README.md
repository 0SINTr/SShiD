![SShiD](docs/SShiD.png)
# 📡 SShiD - Covert Communication via SSID Beacons 📡

![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)
[![Stable Release](https://img.shields.io/badge/version-0.1.0-blue.svg)](https://github.com/0SINTr/SShiD/releases/tag/v0.1.0)
[![Last Commit](https://img.shields.io/github/last-commit/0SINTr/SShiD)](https://github.com/0SINTr/SShiD/commits/main/)

## 📖 **Table of Contents**

- [📡 SShiD: Covert Communication via SSID Beacons](#📡-sshid-covert-communication-via-ssid-beacons)
  - [🔍 Overview](#-overview)
  - [🚀 Features](#-features)
  - [💪 Advantages](#-advantages)
  - [🛠️ Architecture](#-architecture)
  - [🔄 Communication Flow](#-communication-flow)
  - [🕵 System Requirements](#-system-requirements)
  - [🖥️ Monitor Mode](#-monitor-mode)
  - [⚒️ Installation](#-installation)
  - [⛑️ Usage](#-usage)
  - [🚫 Limitations](#-limitations)
  - [🎯 Planned Upgrades](#-planned-upgrades)
  - [⚠️ Disclaimer](#-disclaimer)
  - [📜 License](#-license)
  - [📧 Contact](#-professional-collaborations)

## 🔍 **Overview**

**SShiD** is a proof-of-concept, Linux-based tool that utilizes principles of **network steganography** and enables covert communication by embedding encrypted messages within Wi-Fi beacon frames' **Vendor-Specific Information Elements (IEs)**. This method allows for discreet data transmission without establishing a traditional network connection.

🍀 **NOTE:** This is an ongoing **reasearch project** for educational purposes rather than a full-fledged production-ready tool, so treat it accordingly.

## 🚀 **Features**

- **Covert Communication:** Transmit messages without active network connections.
- **Encryption:** Utilizes ChaCha20-Poly1305 encryption for secure message transmission.
- **Custom SSID Generation:** Creates unique SSIDs based on a shared secret password.
- **Vendor-Specific IEs:** Embeds messages within standard-compliant beacon frames.
- **Channel Specification:** Operates on a user-defined Wi-Fi channel (default is 6).

## 💪 **Advantages**

- **Stealthy Transmission:** By leveraging beacon frames, communication remains passive and less detectable.
- **No Network Association Required:** Devices can exchange information without connecting to an access point.
- **No Single Point of Failure:** Communication cannot be filtered by a firewall or IDS system.
- **Standard Compliance:** Uses Wi-Fi standards, enhancing compatibility with various devices.
- **Encryption Security:** Ensures messages remain confidential and tamper-proof.

## 🛠️ **Architecture**

The project consists of two main components:

1. **Speaker:** Broadcasts beacon frames containing encrypted messages.
2. **Listener:** Sniffs beacon frames and extracts the hidden messages.

Both components use a shared secret password for SSID generation and message encryption/decryption.

## 🔄 **Communication Flow**

1. **Initialization:**
   - **Speaker and Listener** share a secret password before using SShiD.
   - Both set their wireless interfaces to monitor mode on the same channel.

2. **SSID Generation:**
   - The **Speaker** generates a unique SSID by hashing the password.
   - This SSID serves as an identifier for the Listener.
   - The Listener derives the same SSID from the password.

3. **Message Encryption:**
   - The **Speaker** encrypts the message using ChaCha20-Poly1305 with a key derived from the password.

4. **Beacon Frame Construction:**
   - The **Speaker** constructs a beacon frame with:
     - The generated SSID.
     - The encrypted message embedded in a Vendor-Specific IE.
     - Standard IEs like RSN information for compliance.

5. **Broadcasting:**
   - The **Speaker** broadcasts the beacon frames periodically.

6. **Packet Capturing:**
   - The **Listener** captures beacon frames in monitor mode.
   - Filters frames matching the unique SSID.

7. **Message Extraction:**
   - The **Listener** extracts the encrypted message from the Vendor-Specific IE.
   - Decrypts the message using the shared password.

8. **Output:**
   - The decrypted message is displayed to the user.

🍀 **NOTE:** SShiD enables **one-to-many** communication between the **Speaker** and any **Listener** who knows the password. Therefore, the message exchange is **not** bidirectional.

## 🕵 **System Requirements**

- **Operating System:** Linux-based systems (e.g., Ubuntu, Debian, Fedora)
  - Latest release tested and functional on **Ubuntu 24.04**
- **Python Version:** Python 3.8 or higher
- **Dependencies:**
  - `scapy` for packet crafting and sniffing
  - `cryptography` for encryption and decryption
- **Privileges:** Root or sudo access to send or sniff WiFi beacons
- **Network Interface:** Wireless interfaces in **UP** state and **Monitor** mode. **SShiD** will automatically detect and prompt you to select the active interface if multiple are detected.

## 🖥️ **Monitor Mode**

Monitor mode should be enabled on **both** the Speaker and Listener machines prior to using SShiD.
To identify your wireless interface and check if it supports Monitor mode use:
```bash
iw dev
sudo iw list | grep -A 10 "Supported interface modes"
```

To enable Monitor mode and set channel 6 (assuming `wlan0` is your interface) use:
```bash
sudo apt update
sudo apt install aircrack-ng
sudo airmon-ng check kill
sudo airmon-ng start wlan0 6
```
After enabling Monitor mode, your interface will now show up as **wlan0mon**.

Some WiFi cards may show support for Monitor mode but not function properly, for instance when capturing frames. 

To check your wireless adapter driver use:
```bash
lspci -k | grep -A 3 -i network
```
or, for USB adapters:
```bash
lsusb
```

Additionally, check logs for failure messages if your adapter doesn't capture any traffic at all in Monitor mode.
```bash
sudo dmesg | grep -i <driver_name>
```

🍀 **NOTE:** Do your own research on this adapter and any issues related to Monitor mode. Best case scenario, you need a driver update. Otherwise, you need an adapter that supports Monitor mode.

To disable Monitor mode and re-enable the default Managed mode:
```bash
sudo airmon-ng stop wlan0mon
sudo systemctl start NetworkManager
```

## ⚒️ **Installation**

1. **Clone the Repository:**
   ```bash
   git clone https://github.com/0SINTr/SShiD.git
   cd SShiD
   ```

2. **Install Dependencies:**
   ```bash
   sudo apt install python3-scapy
   sudo apt install python3-cryptography
   ```

## ⛑️ **Usage**

Both Speaker and Listener scripts require root privileges to send or sniff beacons. You can run the scripts using `sudo`:

**Speaker:**
   ```
   sudo python3 speaker.py
   ```

**Listener:**
   ```
   sudo python3 listener.py
   ```

## 🚫 Limitations
- **Hardware Compatibility**: Requires wireless adapters that support monitor mode and packet injection.
- **Range Constraints**: Effective communication range is limited to Wi-Fi transmission distances.
- **Legal Compliance**: Users must comply with local laws and regulations regarding wireless transmissions.

## 🎯 Planned Upgrades

- [ ] More testing is needed
- [ ] Improved CLI experience

## ️⚠️ Disclaimer
**SShiD** is intended for educational and authorized security testing purposes only. Unauthorized interception or manipulation of network traffic is illegal and unethical. Users are responsible for ensuring that their use of this tool complies with all applicable laws and regulations. The developers of **SShiD** do not endorse or support any malicious or unauthorized activities. Use this tool responsibly and at your own risk.

## 📜 License
No license is provided for this software, therefore the work is under exclusive copyright by default. Read more about what this means [here](https://choosealicense.com/no-permission/).

## 📧 Professional Collaborations

- **Email Address**:  
  Please direct your inquiries to **sintr.0@pm.me**.

- **Important Guidelines**:  
  - Use a **professional email** or a **ProtonMail** address.
  - Keep your message **concise** and written in **English**.

- **Security Notice**:  
  Emails with **links** or **attachments** will be ignored for security reasons.