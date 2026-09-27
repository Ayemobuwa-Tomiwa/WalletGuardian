# Wallet Guardian v4

Wallet Guardian is a local, read-only test monitor for the OKX Web3 balance API.

## What v4 adds

- Permanent duplicate protection across restarts.
- A persistent activity log at `logs/wallet_guardian.log`.
- A persistent used-mnemonic hash database at `data/used_mnemonic_hashes.txt`.
- Live terminal progress for every wallet and cycle.
- Cycle statistics, runtime, error reporting, and threshold-hit alerts.
- Plaintext mnemonics are **not** written to either persistent file.
- A mnemonic is displayed in the terminal only when that wallet's balance is strictly above the configured threshold.

## Test flow

1. Generate a cryptographically secure BIP-39 mnemonic locally.
2. Hash it with SHA-256 and check the permanent used-hash database.
3. If it has been used before, generate another mnemonic.
4. Derive the Ethereum address locally using `m/44'/60'/0'/0/0`.
5. Send only the derived public address to OKX.
6. Read the address's total USD value.
7. Report wallets whose balance is strictly above the configured threshold.

The mnemonic is never sent to OKX.

## Security note

The permanent duplicate database stores only SHA-256 hashes of generated mnemonics. It does not store plaintext recovery phrases. The activity log also does not store recovery phrases.

If a wallet exceeds the threshold, its mnemonic is printed to the terminal because that is the requested alert behavior. Treat that terminal output as sensitive and do not copy it into public chats, screenshots, or logs.

## Setup

Create/activate the virtual environment and install dependencies:

```powershell
uv pip install -r requirements.txt
```

Copy `.env.example` to `.env` and add your OKX Web3 API credentials.

Then run:

```powershell
python main.py
```

## Configuration

`MNEMONIC_WORDS` may be `12`, `18`, or `24`. Default: `12`.

`THRESHOLD_USD=10.0` means only balances strictly greater than $10.00 trigger an alert. `$10.00` does not trigger.

`WALLET_COUNT=5` checks five newly generated test wallets per cycle.

`CHECK_INTERVAL_SECONDS=10` waits 10 seconds between cycles.

## Persistent files

Created automatically:

```text
logs/
  wallet_guardian.log

data/
  used_mnemonic_hashes.txt
```

Do not delete `data/used_mnemonic_hashes.txt` if you want duplicate protection to continue across restarts.

## Important test limitation

Freshly generated random wallets normally have a $0 balance because they have never received funds. Therefore, random test mode validates mnemonic generation, address derivation, API authentication, and balance retrieval, but it is not expected to produce many `$10+` alerts.

For deterministic testing, use a wallet/address that you control rather than attempting to discover funded third-party wallets randomly.
