import hashlib
import os
import secrets
import time
from datetime import datetime
from pathlib import Path

from bip_utils import Bip39MnemonicGenerator, Bip39SeedGenerator, Bip44, Bip44Coins
from dotenv import load_dotenv

from .okx import OKXBalanceClient


ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT / "data"
LOG_DIR = ROOT / "logs"
USED_HASHES_FILE = DATA_DIR / "used_mnemonic_hashes.txt"
LOG_FILE = LOG_DIR / "wallet_guardian.log"

DATA_DIR.mkdir(exist_ok=True)
LOG_DIR.mkdir(exist_ok=True)
load_dotenv(ROOT / ".env")


class WalletGuardian:
    THRESHOLD_USD = float(os.getenv("THRESHOLD_USD", "10.0"))
    WALLET_COUNT = int(os.getenv("WALLET_COUNT", "5"))
    CHECK_INTERVAL_SECONDS = 0
    MNEMONIC_WORDS = int(os.getenv("MNEMONIC_WORDS", "12"))

    VALID_WORD_COUNTS = {12: 128, 18: 192, 24: 256}

    def __init__(self):
        if self.MNEMONIC_WORDS not in self.VALID_WORD_COUNTS:
            raise ValueError("MNEMONIC_WORDS must be 12, 18, or 24.")
        if self.WALLET_COUNT < 1:
            raise ValueError("WALLET_COUNT must be at least 1.")
        if self.CHECK_INTERVAL_SECONDS < 0:
            raise ValueError("CHECK_INTERVAL_SECONDS cannot be negative.")

        self.used_phrase_hashes = self._load_used_hashes()
        self.client = OKXBalanceClient()
        self.cycle_number = 0
        self.total_checked = 0
        self.total_errors = 0
        self.total_hits = 0
        self.wallets_identified_above_threshold = 0
        self.started_at = time.monotonic()

    @staticmethod
    def _now():
        return datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S")

    @staticmethod
    def _hash_phrase(phrase):
        return hashlib.sha256(phrase.encode("utf-8")).hexdigest()

    def _load_used_hashes(self):
        if not USED_HASHES_FILE.exists():
            return set()

        hashes = set()
        with USED_HASHES_FILE.open("r", encoding="utf-8") as handle:
            for line in handle:
                value = line.strip().lower()
                if len(value) == 64 and all(c in "0123456789abcdef" for c in value):
                    hashes.add(value)
        return hashes

    def _record_phrase_hash(self, phrase):
        phrase_hash = self._hash_phrase(phrase)
        with USED_HASHES_FILE.open("a", encoding="utf-8") as handle:
            handle.write(phrase_hash + "\n")
        self.used_phrase_hashes.add(phrase_hash)

    def log(self, message):
        line = f"[{self._now()}] {message}"
        print(line, flush=True)
        with LOG_FILE.open("a", encoding="utf-8") as handle:
            handle.write(line + "\n")

    def log_file_only(self, message):
        line = f"[{self._now()}] {message}"
        with LOG_FILE.open("a", encoding="utf-8") as handle:
            handle.write(line + "\n")

    def generate_unique_mnemonic(self):
        """Generate a valid BIP-39 mnemonic never used by this installation."""
        strength = self.VALID_WORD_COUNTS[self.MNEMONIC_WORDS]

        while True:
            entropy = secrets.token_bytes(strength // 8)
            phrase = str(Bip39MnemonicGenerator().FromEntropy(entropy))
            phrase_hash = self._hash_phrase(phrase)

            if phrase_hash not in self.used_phrase_hashes:
                self._record_phrase_hash(phrase)
                return phrase

    @staticmethod
    def derive_ethereum_address(phrase):
        """Derive Ethereum address m/44'/60'/0'/0/0 locally from a BIP-39 phrase."""
        seed = Bip39SeedGenerator(phrase).Generate()
        wallet = Bip44.FromSeed(seed, Bip44Coins.ETHEREUM).DeriveDefaultPath()
        return wallet.PublicKey().ToAddress()

    def check_wallet(self, wallet_number):
        phrase = self.generate_unique_mnemonic()
        address = self.derive_ethereum_address(phrase)
        balance = self.client.get_total_value_usd(address)

        return {
            "number": wallet_number,
            "phrase": phrase,
            "address": address,
            "balance": balance,
        }

    def _format_duration(self, seconds):
        seconds = int(seconds)
        hours, remainder = divmod(seconds, 3600)
        minutes, secs = divmod(remainder, 60)
        if hours:
            return f"{hours}h {minutes}m {secs}s"
        if minutes:
            return f"{minutes}m {secs}s"
        return f"{secs}s"

    def print_banner(self):
        print("\n" + "=" * 72, flush=True)
        print("🔔 WALLET GUARDIAN", flush=True)
        print("OKX READ-ONLY TEST MODE | Continuous monitoring | Ctrl+C to stop", flush=True)
        print("=" * 72, flush=True)

    def run_once(self):
        self.cycle_number += 1
        cycle_started = time.monotonic()
        above_threshold = []
        errors = []

        self.log(f"🔄 Cycle #{self.cycle_number} started | {self.WALLET_COUNT} wallet(s) queued")

        for wallet_number in range(1, self.WALLET_COUNT + 1):
            wallet_started = time.monotonic()
            self.log(f"[{wallet_number}/{self.WALLET_COUNT}] Generating unique BIP-39 mnemonic...")

            try:
                phrase = self.generate_unique_mnemonic()
                address = self.derive_ethereum_address(phrase)
                self.log(f"[{wallet_number}/{self.WALLET_COUNT}] Address: {address}")
                self.log(f"[{wallet_number}/{self.WALLET_COUNT}] Querying OKX balance...")

                balance = self.client.get_total_value_usd(address)
                elapsed = time.monotonic() - wallet_started
                self.total_checked += 1

                if balance > self.THRESHOLD_USD:
                    self.wallets_identified_above_threshold += 1
                    self.total_hits += 1
                    result = {
                        "number": wallet_number,
                        "phrase": phrase,
                        "address": address,
                        "balance": balance,
                    }
                    above_threshold.append(result)
                    self.log(
                        f"[{wallet_number}/{self.WALLET_COUNT}] 🚨 ABOVE THRESHOLD: "
                        f"${balance:.2f} | {elapsed:.2f}s"
                    )
                    self.log_file_only(
                        f"ALERT wallet={wallet_number} balance_usd={balance:.2f} "
                        f"address={address} elapsed_seconds={elapsed:.2f}"
                    )
                else:
                    self.log(
                        f"[{wallet_number}/{self.WALLET_COUNT}] Balance: "
                        f"${balance:.2f} | below/equal threshold | {elapsed:.2f}s"
                    )

            except Exception as exc:
                elapsed = time.monotonic() - wallet_started
                self.total_errors += 1
                error_text = str(exc).replace("\n", " ")
                errors.append({"number": wallet_number, "error": error_text})
                self.log(
                    f"[{wallet_number}/{self.WALLET_COUNT}] ❌ ERROR after {elapsed:.2f}s: "
                    f"{error_text}"
                )

        cycle_elapsed = time.monotonic() - cycle_started
        runtime = time.monotonic() - self.started_at

        print("\n" + "-" * 72, flush=True)
        print(f"📊 CYCLE #{self.cycle_number} COMPLETE", flush=True)
        print(f"Checked this cycle : {self.WALLET_COUNT}", flush=True)
        print(f"Above ${self.THRESHOLD_USD:.2f}        : {len(above_threshold)}", flush=True)
        print(f"Wallets identified >${self.THRESHOLD_USD:.2f} : {self.wallets_identified_above_threshold}")
        print(f"Errors             : {len(errors)}", flush=True)
        print(f"Unique phrases     : {len(self.used_phrase_hashes):,} total", flush=True)
        print(f"Cycle duration     : {cycle_elapsed:.2f}s", flush=True)
        print(f"Program runtime    : {self._format_duration(runtime)}", flush=True)
        print("-" * 72, flush=True)

        self.log_file_only(
            f"CYCLE_COMPLETE cycle={self.cycle_number} checked={self.WALLET_COUNT} "
            f"hits={len(above_threshold)} errors={len(errors)} "
            f"unique_phrases={len(self.used_phrase_hashes)} "
            f"duration_seconds={cycle_elapsed:.2f}"
        )

        if above_threshold:
            print("\n🚨🚨🚨 WALLET ALERT 🚨🚨🚨", flush=True)
            print(
                f"{len(above_threshold)} wallet(s) are currently above "
                f"${self.THRESHOLD_USD:.2f}.",
                flush=True,
            )
            for wallet in above_threshold:
                # The mnemonic is intentionally shown ONLY here, after a threshold hit.
                print(
                    f"Wallet {wallet['number']}: ${wallet['balance']:.2f}  "
                    f"{wallet['phrase']}",
                    flush=True,
                )
                print(f"  Address: {wallet['address']}", flush=True)

        if errors:
            print("\n⚠️ ERROR REPORT", flush=True)
            for error in errors:
                print(f"Wallet {error['number']}: {error['error']}", flush=True)

        return cycle_elapsed

    def run(self):
        self.print_banner()
        print(f"Mnemonic length       : {self.MNEMONIC_WORDS} words", flush=True)
        print(f"Threshold             : strictly above ${self.THRESHOLD_USD:.2f}", flush=True)
        print(f"Wallets per cycle     : {self.WALLET_COUNT}", flush=True)
        print(f"Check interval        : {self.CHECK_INTERVAL_SECONDS:g} seconds", flush=True)
        print(f"Previously used hashes : {len(self.used_phrase_hashes):,}", flush=True)
        print(f"Activity log          : {LOG_FILE}", flush=True)
        print(f"Used-phrase database  : {USED_HASHES_FILE}", flush=True)
        print("Seed phrases stay local. Only derived public addresses are sent to OKX.", flush=True)
        print("Mnemonics are never written to the activity log or used-phrase database.", flush=True)
        print("A mnemonic is displayed in the terminal only when its balance is above the threshold.", flush=True)
        print("No transfers, swaps, withdrawals, or transaction signing are implemented.", flush=True)
        print("\nReady. Starting continuous monitoring...\n", flush=True)

        self.log_file_only("PROGRAM_START")

        try:
            while True:
                cycle_elapsed = self.run_once()
                remaining = max(0.0, self.CHECK_INTERVAL_SECONDS)

                if remaining > 0:
                    next_run = datetime.now().astimezone().strftime("%H:%M:%S")
                    self.log(
                        f"⏳ Waiting {remaining:g}s before cycle #{self.cycle_number + 1} "
                        f"(next cycle target: {next_run} + interval)"
                    )
                    time.sleep(remaining)
        except KeyboardInterrupt:
            runtime = time.monotonic() - self.started_at
            self.log("🛑 Wallet Guardian stopped by user (Ctrl+C)")
            self.log_file_only(
                f"PROGRAM_STOP cycles={self.cycle_number} checked={self.total_checked} "
                f"hits={self.total_hits} errors={self.total_errors} "
                f"unique_phrases={len(self.used_phrase_hashes)} "
                f"runtime_seconds={runtime:.2f}"
            )
            print("\nWallet Guardian stopped safely.", flush=True)
