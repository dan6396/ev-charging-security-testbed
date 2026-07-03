# no_cert_client.py
import asyncio
import ssl
import os

from websockets import connect

# secure_server 와 동일 경로 사용
SERVER_URI = os.getenv("SERVER_URI", "wss://localhost:8765/CS-001")
CA_FILE = os.getenv("CA_FILE", "ca.pem")


def make_ssl_context_no_client_cert():
    """
    클라이언트 인증서 없이, CA만 로드한 SSL 컨텍스트.
    secure_server 는 CLIENT_AUTH + CERT_REQUIRED 이므로
    → TLS 핸드셰이크 단계에서 실패해야 정상.
    """
    ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    if CA_FILE and os.path.exists(CA_FILE):
        ctx.load_verify_locations(CA_FILE)
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.check_hostname = False
    else:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    # ❌ client cert / key 안 넣음
    return ctx


async def run():
    ssl_ctx = make_ssl_context_no_client_cert()
    try:
        async with connect(SERVER_URI, ssl=ssl_ctx, subprotocols=["ocpp1.6"]) as ws:
            print("[NO-CERT] connected unexpectedly (this should NOT happen with secure_server)")
    except Exception as e:
        print("[NO-CERT] connection failed as expected:", repr(e))


if __name__ == "__main__":
    asyncio.run(run())
