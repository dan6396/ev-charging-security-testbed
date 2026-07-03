# secure_server.py
import asyncio
import logging
import ssl
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Tuple

import hashlib
import requests
from ocpp.routing import on
from ocpp.v16 import call_result
from ocpp.v16 import ChargePoint as CP
from ocpp.v16.enums import Action, RegistrationStatus
from websockets.server import serve

"""
Secure OCPP 1.6 central system (python-ocpp 기반)
- websockets 최신 버전 호환
- mTLS + CA 검증
- BootNotification에 대한 허용 목록 / 재사용 / 속도 제한
- CN / ID / Serial 바인딩
- firmwareVersion 안에 인코딩된 ts/nonce/hash 기반 무결성 및 replay 방어
- 대시보드로 이벤트 전송
"""

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

HOST = "0.0.0.0"
PORT = 8765
CA_FILE = "ca.pem"
SERVER_CERT = "server.crt"
SERVER_KEY = "server.key"
DASHBOARD_URL = "http://127.0.0.1:5001/events"

# 보안 정책 파라미터
ALLOWED_SERIALS = {"CS-001", "CS-002"}
RATE_WINDOW = 60                 # 초
RATE_MAX = 60                    # RATE_WINDOW 동안 허용하는 최대 요청 수
NONCE_WINDOW = 300               # nonce 재사용 허용 안 하는 시간(초)
TS_MAX_SKEW = 300                # timestamp 허용 편차(초) (±5분)

# 시드(장비별 비밀값) – 실제 환경이면 안전한 저장소에서 가져와야 함
DEVICE_SEEDS = {
    "CS-001": "seed-for-cs-001-very-secret",
    "CS-002": "seed-for-cs-002-very-secret",
}

# 상태 저장소
client_rate = {}          # client_id -> [timestamps]
client_nonces = {}        # client_id -> {nonce: first_seen_ts}


def notify_dashboard(event: dict):
    try:
        requests.post(DASHBOARD_URL, json=event, timeout=1)
    except Exception:
        pass


def is_rate_limited(client_id: str) -> bool:
    now = time.time()
    arr = client_rate.get(client_id, [])
    arr = [t for t in arr if now - t <= RATE_WINDOW]
    arr.append(now)
    client_rate[client_id] = arr
    return len(arr) > RATE_MAX


def extract_cn(ssl_obj) -> Optional[str]:
    """TLS 클라이언트 인증서에서 CN 추출."""
    try:
        cert = ssl_obj.getpeercert()
        if not cert:
            return None
        subj = cert.get("subject", ())
        for attr in subj:
            for k, v in attr:
                if k.lower() in ("commonname", "cn"):
                    return v
        san = cert.get("subjectAltName", ())
        for typ, val in san:
            if typ in ("DNS", "IP"):
                return val
    except Exception:
        logging.debug("cn extract failed", exc_info=True)
    return None


def is_timestamp_invalid(ts: Optional[float]) -> bool:
    """timestamp가 허용 범위를 벗어나는지 확인."""
    if ts is None:
        return True
    try:
        ts = float(ts)
    except Exception:
        return True
    now = time.time()
    return abs(now - ts) > TS_MAX_SKEW


def is_replay_nonce(client_id: str, nonce: Optional[str]) -> bool:
    """
    nonce 기반 replay 방어:
    - NONCE_WINDOW 초 이내에 같은 nonce가 다시 오면 replay로 판정.
    """
    if not nonce:
        return False

    now = time.time()
    store = client_nonces.setdefault(client_id, {})

    # 오래된 nonce 정리
    for n, first_seen in list(store.items()):
        if now - first_seen > NONCE_WINDOW:
            del store[n]

    if nonce in store:
        return True

    store[nonce] = now
    return False


def calc_message_hash(seed: str,
                      client_id: str,
                      serial: str,
                      vendor: str,
                      model: str,
                      nonce: str,
                      ts: float) -> str:
    """
    클라이언트와 동일한 방식으로 hash를 계산해야 함.
    base = f"{seed}|{client_id}|{serial}|{vendor}|{model}|{nonce}|{int(ts)}"
    hash_full = SHA256(base)
    여기서 전체 hexdigest가 길어서, 앞 12자리(= 48bit 정도)를 사용.
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
    return full[:12]   # 클라랑 동일하게 앞 12글자만 사용


def parse_fw_metadata(fw: str) -> Tuple[Optional[float], Optional[str], Optional[str]]:
    """
    firmwareVersion 문자열에서 ts, nonce, hash 파싱.
    형식 예: "ts=1764427870;nonce=n42;hash=abcd1234ef56"
    """
    ts_val = None
    nonce = None
    h = None

    if not fw:
        return None, None, None

    try:
        parts = fw.split(";")
        for part in parts:
            if "=" not in part:
                continue
            k, v = part.split("=", 1)
            k = k.strip().lower()
            v = v.strip()
            if k == "ts":
                try:
                    ts_val = float(v)
                except Exception:
                    ts_val = None
            elif k == "nonce":
                nonce = v
            elif k == "hash":
                h = v
    except Exception:
        logging.debug("Failed to parse firmwareVersion meta", exc_info=True)

    return ts_val, nonce, h


class SecureCentralSystem(CP):
    def __init__(self, charge_point_id, websocket, peername, client_id):
        super().__init__(charge_point_id, websocket)
        self.peername = peername
        self.client_id = client_id
        self.charge_point_id = charge_point_id

    @on(Action.boot_notification)
    async def on_boot_notification(self, charge_point_vendor, charge_point_model, **kwargs):
        """
        BootNotification validation
        - 정상 통신(type=normal, accepted)
        - tamper(type=tamper, rejected)
        - spoof(type=spoof, rejected)
        - replay(type=replay, rejected)
        """
        now = time.time()

        # 1) rate-limit
        if is_rate_limited(self.client_id):
            notify_dashboard({
                "server": "secure",
                "type": "rate-limit",
                "action": "BootNotification",
                "result": "rejected",
                "reason": "rate-limit",
                "peer": self.peername,
                "ts": now,
                "client_id": self.client_id,
            })
            logging.warning("SECURE rate limit exceeded for %s", self.client_id)
            return call_result.BootNotification(
                current_time=datetime.now(timezone.utc).isoformat(),
                interval=0,
                status=RegistrationStatus.rejected,
            )

        # 2) serial 추출
        serial = (
            kwargs.get("charge_box_serial_number")
            or kwargs.get("charge_point_serial_number")
            or kwargs.get("serialNumber")
        )

        # 3) CN / chargePointId / serial 바인딩 검사
        binding_ok = bool(serial) and serial == self.client_id and serial == self.charge_point_id
        if not binding_ok:
            notify_dashboard({
                "server": "secure",
                "type": "spoof",
                "action": "BootNotification",
                "result": "rejected",
                "reason": "id-binding-mismatch",
                "peer": self.peername,
                "ts": now,
                "client_id": self.client_id,
                "serial": serial,
                "cp_id": self.charge_point_id,
            })
            logging.warning("SECURE ID binding mismatch")
            return call_result.BootNotification(
                current_time=datetime.now(timezone.utc).isoformat(),
                interval=0,
                status=RegistrationStatus.rejected,
            )

        # 4) whitelist
        if serial not in ALLOWED_SERIALS:
            notify_dashboard({
                "server": "secure",
                "type": "spoof",
                "action": "BootNotification",
                "result": "rejected",
                "reason": "unknown-serial",
                "peer": self.peername,
                "ts": now,
                "client_id": self.client_id,
                "serial": serial,
            })
            logging.warning("SECURE unknown serial")
            return call_result.BootNotification(
                current_time=datetime.now(timezone.utc).isoformat(),
                interval=0,
                status=RegistrationStatus.rejected,
            )

        # 5) firmwareVersion 파싱
        fw = kwargs.get("firmware_version")
        ts_val, nonce, recv_hash = parse_fw_metadata(fw)

        # 5-1) timestamp invalid → tamper 공격
        if is_timestamp_invalid(ts_val):
            notify_dashboard({
                "server": "secure",
                "type": "tamper",
                "action": "BootNotification",
                "result": "rejected",
                "reason": "timestamp-invalid",
                "peer": self.peername,
                "ts": now,
                "client_id": self.client_id,
                "serial": serial,
            })
            logging.warning("SECURE timestamp invalid")
            return call_result.BootNotification(
                current_time=datetime.now(timezone.utc).isoformat(),
                interval=0,
                status=RegistrationStatus.rejected,
            )

        # 5-2) replay 체크
        if is_replay_nonce(self.client_id, nonce):
            notify_dashboard({
                "server": "secure",
                "type": "replay",
                "action": "BootNotification",
                "result": "rejected",
                "reason": "replay-nonce",
                "peer": self.peername,
                "ts": now,
                "client_id": self.client_id,
                "serial": serial,
            })
            logging.warning("SECURE replay")
            return call_result.BootNotification(
                current_time=datetime.now(timezone.utc).isoformat(),
                interval=0,
                status=RegistrationStatus.rejected,
            )

        # 5-3) hash 검증
        seed = DEVICE_SEEDS.get(serial)
        if not seed:
            notify_dashboard({
                "server": "secure",
                "type": "tamper",
                "action": "BootNotification",
                "result": "rejected",
                "reason": "no-seed",
                "peer": self.peername,
                "ts": now,
                "client_id": self.client_id,
                "serial": serial,
            })
            logging.warning("SECURE no seed for serial=%s", serial)
            return call_result.BootNotification(
                current_time=datetime.now(timezone.utc).isoformat(),
                interval=0,
                status=RegistrationStatus.rejected,
            )

        if not recv_hash:
            notify_dashboard({
                "server": "secure",
                "type": "tamper",
                "action": "BootNotification",
                "result": "rejected",
                "reason": "missing-hash",
                "peer": self.peername,
                "ts": now,
                "client_id": self.client_id,
                "serial": serial,
            })
            logging.warning("SECURE missing hash")
            return call_result.BootNotification(
                current_time=datetime.now(timezone.utc).isoformat(),
                interval=0,
                status=RegistrationStatus.rejected,
            )

        try:
            expected_hash = calc_message_hash(
                seed, self.client_id, serial,
                charge_point_vendor, charge_point_model,
                nonce or "", float(ts_val)
            )
        except Exception as e:
            notify_dashboard({
                "server": "secure",
                "type": "tamper",
                "action": "BootNotification",
                "result": "rejected",
                "reason": f"hash-calc-error:{e}",
                "peer": self.peername,
                "ts": now,
                "client_id": self.client_id,
                "serial": serial,
            })
            logging.exception("SECURE hash calc error")
            return call_result.BootNotification(
                current_time=datetime.now(timezone.utc).isoformat(),
                interval=0,
                status=RegistrationStatus.rejected,
            )

        if recv_hash != expected_hash:
            notify_dashboard({
                "server": "secure",
                "type": "tamper",
                "action": "BootNotification",
                "result": "rejected",
                "reason": "hash-mismatch",
                "peer": self.peername,
                "ts": now,
                "client_id": self.client_id,
                "serial": serial,
                "expected_hash": expected_hash,
                "recv_hash": recv_hash,
            })
            logging.warning("SECURE hash mismatch")
            return call_result.BootNotification(
                current_time=datetime.now(timezone.utc).isoformat(),
                interval=0,
                status=RegistrationStatus.rejected,
            )

        # 6) 모든 검증 통과 → 정상 통신
        notify_dashboard({
            "server": "secure",
            "type": "normal",   # Normal / Replay 첫 번째 부팅 모두 여기로 들어옴
            "action": "BootNotification",
            "result": "accepted",
            "reason": "ok",
            "peer": self.peername,
            "ts": now,
            "client_id": self.client_id,
            "serial": serial,
        })
        logging.info("SECURE accepted BootNotification")
        return call_result.BootNotification(
            current_time=datetime.now(timezone.utc).isoformat(),
            interval=60,
            status=RegistrationStatus.accepted,
        )


async def on_connect(websocket):
    """websockets 최신 버전용 핸들러 (dashboard 기록 기능 포함)."""
    try:
        path = websocket.request.path
    except Exception:
        path = "/"

    # 1) subprotocol mismatch → Bad Subprotocol Attack 실패
    if websocket.subprotocol != "ocpp1.6":
        notify_dashboard({
            "server": "secure",
            "type": "bad-subprotocol",
            "action": "Connect",
            "result": "rejected",
            "reason": f"invalid-subprotocol-{websocket.subprotocol}",
            "peer": websocket.remote_address,
            "ts": time.time(),
        })
        logging.warning("SECURE invalid subprotocol: %s", websocket.subprotocol)
        await websocket.close()
        return

    peer = websocket.remote_address
    ssl_obj = websocket.transport.get_extra_info("ssl_object")

    # 2) non-TLS → 거의 안 들어오지만, 방어 로직 유지
    if not ssl_obj:
        notify_dashboard({
            "server": "secure",
            "type": "no-cert",
            "action": "Connect",
            "result": "rejected",
            "reason": "non-tls-connection",
            "peer": peer,
            "ts": time.time(),
        })
        logging.warning("SECURE rejecting non-TLS connection")
        await websocket.close()
        return

    client_id = extract_cn(ssl_obj) or "<no-cn>"
    if client_id == "<no-cn>":
        notify_dashboard({
            "server": "secure",
            "type": "no-cert",
            "action": "Connect",
            "result": "rejected",
            "reason": "no-common-name",
            "peer": peer,
            "ts": time.time(),
        })
        logging.warning("SECURE missing CN in certificate")
        await websocket.close()
        return

    charge_point_id = path.strip("/") or client_id

    logging.info(
        "SECURE connection from %s id=%s cp_id=%s",
        peer,
        client_id,
        charge_point_id,
    )

    cp = SecureCentralSystem(charge_point_id, websocket, peername=peer, client_id=client_id)

    # cp.start() 중 ConnectionClosedOK(정상 종료)는 이벤트로 안 보냄
    try:
        await cp.start()
    except Exception as e:
        msg = repr(e)
        if "ConnectionClosedOK" in msg or "code=1000" in msg:
            # 정상 종료 → 이벤트 안 보냄
            logging.info("SECURE normal close %s", peer)
        else:
            notify_dashboard({
                "server": "secure",
                "type": "connection-error",
                "action": "Connect",
                "result": "rejected",
                "reason": msg,
                "peer": peer,
                "ts": time.time(),
            })
            logging.error("SECURE connection handler failed", exc_info=True)

    logging.info("SECURE connection closed %s", peer)


def build_ssl_context():
    if not Path(SERVER_CERT).exists() or not Path(SERVER_KEY).exists():
        raise FileNotFoundError("server certificate/key not found")

    ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ctx.load_cert_chain(certfile=SERVER_CERT, keyfile=SERVER_KEY)
    if Path(CA_FILE).exists():
        ctx.load_verify_locations(cafile=CA_FILE)
        ctx.verify_mode = ssl.CERT_REQUIRED
    else:
        logging.warning("SECURE running without CA_FILE")
    return ctx


async def main():
    ssl_ctx = build_ssl_context()
    async with serve(on_connect, HOST, PORT, ssl=ssl_ctx, subprotocols=["ocpp1.6"]):
        logging.info("Secure OCPP server listening on %s:%d (ocpp1.6, mTLS)", HOST, PORT)
        await asyncio.Future()


if __name__ == "__main__":
    asyncio.run(main())
