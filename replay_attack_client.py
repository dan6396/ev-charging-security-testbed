# replay_attack_client.py
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

CLIENT_ID = "CS-001"
SERIAL = "CS-001"
VENDOR = "DemoChargerCorp"
MODEL = "SecureX1"


async def run():
    ws = await connect_ocpp()

    seed = DEVICE_SEEDS[SERIAL]

    # 첫 번째(정상) BootNotification
    ts = time.time()
    nonce = generate_nonce()

    h = calc_message_hash(
        seed=seed,
        client_id=CLIENT_ID,
        serial=SERIAL,
        vendor=VENDOR,
        model=MODEL,
        nonce=nonce,
        ts=ts,
    )

    fw = build_firmware_version(ts, nonce, h)

    payload = build_boot_payload(
        vendor=VENDOR,
        model=MODEL,
        serial=SERIAL,
        firmware_version=fw,
    )

    msg1 = make_call_message("BootNotification", payload)
    print("[REPLAY] first sending:", msg1)
    await ws.send(json.dumps(msg1))
    reply1 = await ws.recv()
    print("[REPLAY] first reply:", reply1)

    # 두 번째: 동일한 ts/nonce/hash 그대로 재사용 → replay 공격
    msg2 = make_call_message("BootNotification", payload)
    print("[REPLAY] second sending (replay):", msg2)
    await ws.send(json.dumps(msg2))
    reply2 = await ws.recv()
    print("[REPLAY] second reply:", reply2)

    await ws.close()


if __name__ == "__main__":
    asyncio.run(run())
