# bad_subprotocol_client.py
import asyncio
from websockets import connect, WebSocketException
from client_common import make_ssl_context, SERVER_URI

TIMEOUT = 2   # vulnerable server가 응답 없을 때 기다리는 최대 시간


async def run():
    print("=" * 80)
    print("🔥 Running: Bad Subprotocol Attack")
    print("=" * 80)

    ssl_ctx = make_ssl_context()

    try:
        # 🔥 고의로 잘못된 subprotocol 사용
        async with connect(
            SERVER_URI,
            ssl=ssl_ctx,
            subprotocols=["not-ocpp"]
        ) as ws:

            print("[BAD-SUBPROTO] connected, trying to see server behavior...")

            try:
                # 서버가 OCPP 1.6이 아니므로 아무 응답도 안 할 수 있음 → timeout 필요
                await ws.send("hello-but-not-ocpp")

                reply = await asyncio.wait_for(ws.recv(), timeout=TIMEOUT)
                print("[BAD-SUBPROTO] reply:", reply)

            except asyncio.TimeoutError:
                print(f"[BAD-SUBPROTO] no response for {TIMEOUT} seconds → moving to next attack...")

            except WebSocketException as e:
                print("[BAD-SUBPROTO] websocket error:", repr(e))

            except Exception as e:
                print("[BAD-SUBPROTO] recv/send error:", repr(e))

    except Exception as e:
        print("[BAD-SUBPROTO] connection failed / closed as expected:", repr(e))

    print("[BAD-SUBPROTO] attack finished.\n")


if __name__ == "__main__":
    asyncio.run(run())
