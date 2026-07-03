# flood_attack_client.py
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

TOTAL_REQUESTS = 120   # 60개 이상이면 rate-limit 걸리게 설계됨
DELAY_SEC = 0.05       # 50ms 간격


async def run():
    ws = await connect_ocpp()
    seed = DEVICE_SEEDS[SERIAL]

    for i in range(TOTAL_REQUESTS):
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

        msg = make_call_message("BootNotification", payload)
        print(f"[FLOOD] sending {i+1}/{TOTAL_REQUESTS}")
        await ws.send(json.dumps(msg))

        try:
            reply = await ws.recv()
            print("[FLOOD] reply:", reply)
        except Exception as e:
            print("[FLOOD] recv error:", e)
            break

        await asyncio.sleep(DELAY_SEC)

    await ws.close()


if __name__ == "__main__":
    asyncio.run(run())
