# vulnerable_server.py
import asyncio
import logging
import ssl
import uuid
import time
import requests
from datetime import datetime, timezone

from websockets.server import serve

from ocpp.v16 import ChargePoint as CP
from ocpp.routing import on
from ocpp.v16.enums import Action, RegistrationStatus
from ocpp.v16 import call_result

"""
취약한 OCPP 1.6 서버
- 인증서 CN 검사 없음
- serial whitelist 없음
- hash / nonce / timestamp 검증 없음
- replay 검증 없음
- Rate-limit 없음
"""

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

HOST = "0.0.0.0"
PORT = 8766
SERVER_CERT = "server.crt"
SERVER_KEY = "server.key"
DASHBOARD_URL = "http://127.0.0.1:5001/events"


def notify_dashboard(event: dict):
    """Dashboard로 이벤트 전송."""
    try:
        requests.post(DASHBOARD_URL, json=event, timeout=1)
    except Exception:
        # 대시보드 죽어 있어도 서버가 죽지 않도록 무시
        pass


class VulnerableCentralSystem(CP):
    def __init__(self, charge_point_id, websocket, peer):
        super().__init__(charge_point_id, websocket)
        self.peer = peer

    # ⚠️ 여기 인자 이름이 중요함: snake_case 로 맞춰야 한다!
    @on(Action.boot_notification)
    async def on_boot_notification(
        self,
        charge_point_vendor,
        charge_point_model,
        charge_box_serial_number=None,
        firmware_version=None,
        **kwargs,
    ):
        """
        매우 취약한 BootNotification:
        - 어떤 serial / hash / timestamp / nonce / CN 이 와도 모두 Accept.
        - 안전한 검증 없음.
        """

        serial = charge_box_serial_number
        firmware = firmware_version

        logging.info(
            "VULN accepted BootNotification from %s (vendor=%s model=%s serial=%s)",
            self.peer,
            charge_point_vendor,
            charge_point_model,
            serial,
        )

        # dashboard push
        ev = {
            "server": "vulnerable",
            "type": "accepted-vulnerable",
            "action": "BootNotification",
            "peer": self.peer,
            "result": "accepted",
            "reason": "ok",
            "ts": time.time(),
            "client_id": self.id,          # ← 여기 수정됨!!!
            "vendor": charge_point_vendor,
            "model": charge_point_model,
            "serial": serial,
            "firmware": firmware,
        }
        notify_dashboard(ev)

        # currentTime 은 반드시 ISO8601 문자열이어야 함
        now_str = datetime.now(timezone.utc).isoformat()

        # ✅ 반드시 call_result.BootNotification 객체로 반환해야 한다
        return call_result.BootNotification(
            current_time=now_str,
            interval=60,
            status=RegistrationStatus.accepted,
        )


async def on_connect(websocket):
    """websockets 최신버전용 연결 핸들러."""
    try:
        path = websocket.request.path
    except Exception:
        path = "/"

    cp_id = path.strip("/") or f"vuln-{uuid.uuid4()}"
    peer = websocket.remote_address

    logging.info(
        "VULN connection open from %s cp_id=%s subproto=%s",
        peer,
        cp_id,
        websocket.subprotocol,
    )

    cp = VulnerableCentralSystem(cp_id, websocket, peer)
    await cp.start()

    logging.info("VULN connection closed %s", peer)


def build_ssl_context():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(SERVER_CERT, SERVER_KEY)
    return ctx


async def main():
    ssl_ctx = build_ssl_context()

    logging.info("VULN starting with TLS (wss) using server.crt/server.key")

    async with serve(
        on_connect,
        HOST,
        PORT,
        ssl=ssl_ctx,
        subprotocols=["ocpp1.6"],
    ):
        logging.info("Vulnerable OCPP server listening on %s:%d", HOST, PORT)
        await asyncio.Future()


if __name__ == "__main__":
    asyncio.run(main())
