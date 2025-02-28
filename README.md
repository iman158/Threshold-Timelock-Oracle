# Threshold-Timelock-Oracle
A secure, decentralized, and time-locked signing oracle using VDFs and threshold BLS signatures.
🔹 Features

    ✅ Threshold Cryptography: Uses BLS signatures with DKG-based key generation.
    ⏳ Timelock Security: Implements Verifiable Delay Functions (VDFs) to enforce time-based cryptographic delays.
    🌐 Asynchronous Networking: Uses aiohttp to request and aggregate threshold signature shares.
    🔍 Verifiable Outputs: Combines threshold signatures only if the required number of valid shares is collected.

⚙️ How It Works

    Run DKG to generate a threshold key among participants.
    Compute a Verifiable Delay Function (VDF) to ensure a time delay.
    Threshold sign the VDF output using a decentralized signing process.

📌 Installation & Usage
Requirements

    Python 3.8+
    aiohttp
    bls, vdf, dkg (custom libraries or installable dependencies)

Run the Oracle

python threshold_timelock_oracle.py
