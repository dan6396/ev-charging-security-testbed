# spoof_serial_client.py
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

CLIENT_ID = "CS-001"          # 인증서 CN
REAL_SERIAL = "CS-001"        # 실제 장비 serial
SPOOF_SERIAL = "FAKE-999"     # 공격자가 가장하려는 다른 충전기
VENDOR = "DemoChargerCorp"
MODEL = "SecureX1"


async def run():
    ws = await connect_ocpp()

    seed = DEVICE_SEEDS[REAL_SERIAL]  # 실제 장비 seed

    ts = time.time()
    nonce = generate_nonce()

    # 공격자는 payload 에서만 serial 을 바꿈
    # hash 계산 시에도 SPOOF_SERIAL 사용 (서버는 binding check에서 먼저 걸림)
    spoof_hash = calc_message_hash(
        seed=seed,
        client_id=CLIENT_ID,
        serial=SPOOF_SERIAL,
        vendor=VENDOR,
        model=MODEL,
        nonce=nonce,
        ts=ts,
    )

    fw = build_firmware_version(ts, nonce, spoof_hash)

    payload = build_boot_payload(
        vendor=VENDOR,
        model=MODEL,
        serial=SPOOF_SERIAL,  # 여기서 시리얼 위장
        firmware_version=fw,
    )

    msg = make_call_message("BootNotification", payload)
    print("[SPOOF] sending:", msg)

    await ws.send(json.dumps(msg))
    reply = await ws.recv()
    print("[SPOOF] reply:", reply)

    await ws.close()


if __name__ == "__main__":
    asyncio.run(run())
