import base64
import hashlib
import hmac
import os
from datetime import datetime, timezone
from urllib.parse import urlencode

import requests


class OKXBalanceClient:
    """Read-only OKX Web3 balance client."""

    BASE_URL = "https://web3.okx.com"
    PATH = "/api/v6/dex/balance/total-value-by-address"

    def __init__(self, timeout=20):
        self.api_key = os.getenv("OKX_API_KEY", "").strip()
        self.api_secret = os.getenv("OKX_API_SECRET", "").strip()
        self.passphrase = os.getenv("OKX_API_PASSPHRASE", "").strip()
        self.timeout = timeout

        missing = []
        if not self.api_key:
            missing.append("OKX_API_KEY")
        if not self.api_secret:
            missing.append("OKX_API_SECRET")
        if not self.passphrase:
            missing.append("OKX_API_PASSPHRASE")
        if missing:
            raise RuntimeError(
                "Missing OKX environment variables: " + ", ".join(missing)
            )

    def _request(self, query):
        timestamp = datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
        query_string = urlencode(query)
        request_path = self.PATH + (f"?{query_string}" if query_string else "")
        prehash = timestamp + "GET" + request_path
        signature = base64.b64encode(
            hmac.new(
                self.api_secret.encode("utf-8"),
                prehash.encode("utf-8"),
                hashlib.sha256,
            ).digest()
        ).decode("utf-8")

        headers = {
            "OK-ACCESS-KEY": self.api_key,
            "OK-ACCESS-SIGN": signature,
            "OK-ACCESS-PASSPHRASE": self.passphrase,
            "OK-ACCESS-TIMESTAMP": timestamp,
            "Content-Type": "application/json",
        }

        response = requests.get(
            self.BASE_URL + request_path,
            headers=headers,
            timeout=self.timeout,
        )
        response.raise_for_status()
        payload = response.json()

        if str(payload.get("code", "0")) != "0":
            raise RuntimeError(
                f"OKX API error {payload.get('code')}: {payload.get('msg', 'Unknown error')}"
            )

        return payload

    def get_total_value_usd(self, address, chain_id="1"):
        """Return the total USD value for an Ethereum address."""
        payload = self._request(
            {
                "address": address,
                "chains": chain_id,
                "assetType": "0",
            }
        )

        data = payload.get("data") or []
        if not data:
            return 0.0

        total_value = data[0].get("totalValue", "0")
        return float(total_value or 0)
