# client_normal.py
import asyncio
import time
import hashlib
import json
import os

from client_common import (
    connect_ocpp,
    make_call_message,
    DEVICE_SEEDS,
)

# CN (클라이언트 인증서의 Common Name) — 네 cert CN에 맞게
CLIENT_ID = os.getenv("CLIENT_ID", "CS-001")

# 이 충전기의 논리적인 serial
SERIAL = os.getenv("SERIAL", "CS-001")

VENDOR = "DemoChargerCorp"
MODEL = "SecureX1"


def calc_message_hash(seed: str,
                      client_id: str,
                      serial: str,
                      vendor: str,
                      model: str,
                      nonce: str,
                      ts: float) -> str:
    """
    서버와 동일한 방식으로 hash 계산.
    base = f"{seed}|{client_id}|{serial}|{vendor}|{model}|{nonce}|{int(ts)}"
    SHA256(base).hexdigest()[:12]
    """
    parts = [
        seed,
        client_id,
        serial,
        vendor,
        model,
        nonce,
        str(int(ts)),
    ]
    base = "|".join(parts)
    full = hashlib.sha256(base.encode("utf-8")).hexdigest()
    return full[:12]


def build_firmware_version(seed: str) -> str:
    """
    firmwareVersion에 들어갈 메타데이터 문자열 생성.
    길이 50 이하: "ts=...;nonce=...;hash=12hex"
    """
    ts = time.time()
    # nonce를 짧게 유지 (예: n42)
    nonce = f"n{int(ts) % 100}"
    h = calc_message_hash(
        seed=seed,
        client_id=CLIENT_ID,
        serial=SERIAL,
        vendor=VENDOR,
        model=MODEL,
        nonce=nonce,
        ts=ts,
    )
    fw = f"ts={int(ts)};nonce={nonce};hash={h}"
    # 디버깅용 출력
    # print("firmwareVersion:", fw, "len=", len(fw))
    return fw


async def run():
    seed = DEVICE_SEEDS.get(SERIAL)
    if not seed:
        print(f"[ERROR] No seed configured for serial={SERIAL}")
        return

    ws = await connect_ocpp()
    try:
        fw_meta = build_firmware_version(seed)

        payload = {
            "chargePointVendor": VENDOR,
            "chargePointModel": MODEL,
            "chargeBoxSerialNumber": SERIAL,
            # 여기 안에 ts/nonce/hash 숨김
            "firmwareVersion": fw_meta,
        }

        msg = make_call_message("BootNotification", payload)
        print("[NORMAL] sending:", msg)
        await ws.send(json.dumps(msg))

        reply_raw = await ws.recv()
        print("[NORMAL] reply:", reply_raw)

    finally:
        await ws.close()


if __name__ == "__main__":
    asyncio.run(run())
