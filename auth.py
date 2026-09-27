"""
Автентифікація. Паролі: hash_password/verify_password — hashlib.pbkdf2_hmac
з унікальною сіллю на користувача, порівняння хешів через hmac.compare_digest
(захист від timing-атак). Токени: create_token/verify_token — самописний
HMAC-SHA256 токен (payload.sig, base64url), підписаний SECRET_KEY з .env,
термін дії TOKEN_TTL_SECONDS.
"""

import base64
import hashlib
import hmac
import json
import os
import time

from dotenv import load_dotenv

load_dotenv()

PBKDF2_ITERATIONS = 100_000
SECRET_KEY = os.getenv("SECRET_KEY", "")
TOKEN_TTL_SECONDS = 8 * 3600  # 8 годин

if not SECRET_KEY:
    print("[auth] Увага: SECRET_KEY не задано в .env — токени підписуються "
          "тимчасовим ключем лише для цього процесу (недійсні після перезапуску).")
    SECRET_KEY = os.urandom(32).hex()


def hash_password(password: str, salt: bytes = None) -> tuple[str, str]:
    """Повертає (hash_hex, salt_hex). Якщо salt не задано — генерує новий."""
    if salt is None:
        salt = os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS)
    return digest.hex(), salt.hex()


def verify_password(password: str, stored_hash_hex: str, salt_hex: str) -> bool:
    salt = bytes.fromhex(salt_hex)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS)
    return hmac.compare_digest(digest.hex(), stored_hash_hex)


def _b64encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64decode(s: str) -> bytes:
    padding = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + padding)


def _sign(payload_b64: str) -> str:
    sig = hmac.new(SECRET_KEY.encode("utf-8"), payload_b64.encode("ascii"), hashlib.sha256).digest()
    return _b64encode(sig)


def create_token(user_id: int, ttl_seconds: int = TOKEN_TTL_SECONDS) -> str:
    """HMAC-SHA256 токен формату <payload_b64>.<sig_b64>. payload = {user_id, exp}."""
    payload = {"user_id": user_id, "exp": int(time.time()) + ttl_seconds}
    payload_b64 = _b64encode(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    return f"{payload_b64}.{_sign(payload_b64)}"


def verify_token(token: str):
    """Повертає user_id (int) при валідному й непростроченому токені, інакше None."""
    if not token or "." not in token:
        return None
    payload_b64, sig_b64 = token.rsplit(".", 1)
    if not hmac.compare_digest(sig_b64, _sign(payload_b64)):
        return None
    try:
        payload = json.loads(_b64decode(payload_b64))
    except Exception:
        return None
    if not isinstance(payload, dict) or "user_id" not in payload or "exp" not in payload:
        return None
    if payload["exp"] < time.time():
        return None
    return payload["user_id"]
