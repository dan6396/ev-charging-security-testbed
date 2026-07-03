# tamper_attack_client.py
import asyncio
import json
import time

from client_common import (
    connect_ocpp,
    make_call_message,
    DEVICE_SEEDS,
    generate_nonce,
    calc_message_hash,
    build_firmware_version,
    build_boot_payload,
)

CLIENT_ID = "CS-001"          # 🔥 반드시 인증서 CN과 동일
SERIAL = "CS-001"
VENDOR = "DemoChargerCorp"
MODEL = "SecureX1"


async def run():
    ws = await connect_ocpp()

    seed = DEVICE_SEEDS[SERIAL]

    # 정상적인 ts / nonce
    ts = time.time()
    nonce = generate_nonce()

    # 공격 포인트: 잘못된 seed 사용 (공격자는 진짜 seed를 모른다고 가정)
    wrong_seed = "attacker-does-not-know-real-seed"
    tampered_hash = calc_message_hash(
        seed=wrong_seed,
        client_id=CLIENT_ID,
        serial=SERIAL,
        vendor=VENDOR,
        model=MODEL,
        nonce=nonce,
        ts=ts,
    )

    fw = build_firmware_version(ts, nonce, tampered_hash)

    payload = build_boot_payload(
        vendor=VENDOR,
        model=MODEL,
        serial=SERIAL,
        firmware_version=fw,
    )

    msg = make_call_message("BootNotification", payload)
    print("[TAMPER] sending:", msg)

    await ws.send(json.dumps(msg))
    reply = await ws.recv()
    print("[TAMPER] reply:", reply)

    await ws.close()


if __name__ == "__main__":
    asyncio.run(run())
