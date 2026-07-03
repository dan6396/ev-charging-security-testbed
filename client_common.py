# client_common.py
import ssl
import os
import uuid
import json
import time
import random
import string
import hashlib

from websockets import connect

# 🔧 서버 URI (cp_id 포함)
SERVER_URI = os.getenv("SERVER_URI", "wss://localhost:8766/CS-001")

# 🔐 인증서 경로 (네 환경에 맞게 유지)
CA_FILE = os.getenv("CA_FILE", "ca.pem")
CLIENT_CERT = os.getenv("CLIENT_CERT", "client.crt")
CLIENT_KEY = os.getenv("CLIENT_KEY", "client.key")

# ⚠️ 반드시 secure_server.py 와 동일해야 함
DEVICE_SEEDS = {
    "CS-001": "seed-for-cs-001-very-secret",
    "CS-002": "seed-for-cs-002-very-secret",
}


def make_ssl_context():
    """
    mTLS용 SSL 컨텍스트 생성.
    - CA 검증
    - client.crt / client.key 로 클라이언트 인증서 설정
    """
    ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    if CA_FILE and os.path.exists(CA_FILE):
        ctx.load_verify_locations(CA_FILE)
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.check_hostname = False  # localhost 테스트
    else:
        print("[WARN] CA_FILE not found, disabling verification (DEMO ONLY)")
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

    if CLIENT_CERT and CLIENT_KEY and os.path.exists(CLIENT_CERT) and os.path.exists(CLIENT_KEY):
        ctx.load_cert_chain(certfile=CLIENT_CERT, keyfile=CLIENT_KEY)
    else:
        print("[WARN] client cert/key not found; TLS handshake may fail")

    return ctx


def make_call_message(action: str, payload: dict) -> list:
    """
    OCPP 1.6 프레임: [2, uniqueId, action, payload]
    """
    unique_id = str(uuid.uuid4())
    return [2, unique_id, action, payload]


async def connect_ocpp():
    """
    OCPP 1.6 subprotocol로 서버에 연결.
    """
    ssl_ctx = make_ssl_context()
    ws = await connect(SERVER_URI, ssl=ssl_ctx, subprotocols=["ocpp1.6"])
    return ws


def generate_nonce(length: int = 4) -> str:
    """
    간단한 nonce 생성. 예: n4821
    """
    digits = "".join(random.choice(string.digits) for _ in range(length))
    return f"n{digits}"


def calc_message_hash(
    seed: str,
    client_id: str,
    serial: str,
    vendor: str,
    model: str,
    nonce: str,
    ts: float,
) -> str:
    """
    secure_server.calc_message_hash 와 1:1 대응.
    base = f"{seed}|{client_id}|{serial}|{vendor}|{model}|{nonce}|{int(ts)}"
    SHA256 후, 앞 12글자만 사용.
    """
    parts = [
        seed,
        client_id or "",
        serial or "",
        vendor or "",
        model or "",
        nonce or "",
        str(int(ts)),
    ]
    base = "|".join(parts)
    full = hashlib.sha256(base.encode("utf-8")).hexdigest()
    return full[:12]


def build_firmware_version(ts: float, nonce: str, h: str) -> str:
    """
    firmwareVersion 필드에 들어갈 문자열 구성.
    예: "ts=1764588906;nonce=n6;hash=b37c74f74e80"
    """
    return f"ts={int(ts)};nonce={nonce};hash={h}"


def build_boot_payload(
    vendor: str,
    model: str,
    serial: str,
    firmware_version: str,
) -> dict:
    """
    BootNotification 표준 payload 생성 (camelCase 키)
    """
    return {
        "chargePointVendor": vendor,
        "chargePointModel": model,
        "chargeBoxSerialNumber": serial,
        "firmwareVersion": firmware_version,
    }
