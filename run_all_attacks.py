# run_all_attacks.py (FINAL CLEAN VERSION)

import subprocess
import time
import requests

DASHBOARD_URL = "http://127.0.0.1:5001/events"


# ---------------------------------------------------------
# ✅ 중복 제거된 최종 공격 목록 (6개)
# ---------------------------------------------------------
ATTACKS = [
    ("Normal Client", "python client_normal.py"),
    ("Tamper Attack", "python tamper_attack_client.py"),
    ("Serial Spoofing", "python spoof_serial_client.py"),
    ("Replay Attack", "python replay_attack_client.py"),
    ("Bad Subprotocol Attack", "python bad_subprotocol_client.py"),
]


def notify(ev: dict):
    try:
        requests.post(DASHBOARD_URL, json=ev, timeout=1)
    except:
        pass


def run_cmd(name: str, cmd: str):
    print("\n" + "=" * 80)
    print(f"🔥 Running: {name}")
    print("=" * 80 + "\n")

    try:
        subprocess.run(cmd, shell=True, check=False)
    except Exception as e:
        print(f"[{name}] Error:", e)


def main():
    print("=== OCPP Secure Server Attack Demonstration Runner ===\n")

    for name, cmd in ATTACKS:
        run_cmd(name, cmd)

        # ---------------------------------------------------
        # Normal / Tamper / Spoof / Replay / Bad-Subproto:
        #    → 서버가 이미 이벤트를 보내므로 dashboard에 안 보낸다
        # ---------------------------------------------------

        if name == "No-Cert Attack":
            # Vulnerable → 인증서 없어도 Accept
            notify({
                "server": "vulnerable",
                "type": "no-cert",
                "action": "Connect",
                "result": "accepted",
                "reason": "no-cert-allowed",
                "ts": time.time(),
            })

            # Secure → TLS handshake에서 실패 → 방어 성공
            notify({
                "server": "secure",
                "type": "no-cert",
                "action": "Connect",
                "result": "rejected",
                "reason": "tls-handshake-failed",
                "ts": time.time(),
            })

        print("\n⏳ Waiting 1.5 sec...\n")
        time.sleep(1.5)

    print("\n🎉 All attacks completed. Check dashboard!\n")


if __name__ == "__main__":
    main()
