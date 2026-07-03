# OCPP Mini Security Lab

OCPP 1.6(전기차 충전기 ↔ 중앙 시스템 통신 프로토콜) 환경에서 발생할 수 있는 공격을 재현하고,
동일한 공격에 대해 **취약한 서버**와 **보안이 적용된 서버**가 어떻게 다르게 반응하는지
실시간 대시보드로 비교하는 미니 프로젝트입니다.

## 배경

OCPP는 실제 전기차 충전 인프라에서 널리 쓰이지만, 스펙 자체는 메시지 위변조·재전송·인증서 검증 우회 같은
공격을 막기 위한 강제 규정이 약합니다. 이 프로젝트는 같은 `BootNotification` 흐름을 두 종류의 서버에
동시에 흘려보내, "검증 로직이 없으면 실제로 무슨 일이 벌어지는지"를 눈으로 확인할 수 있게 만들었습니다.

## 구성

| 컴포넌트 | 설명 |
|---|---|
| `vulnerable_server.py` | 인증서 CN 검사, serial whitelist, hash/nonce/timestamp 검증, rate-limit이 전혀 없는 서버. 어떤 요청이든 Accept. |
| `secure_server.py` | mTLS + CA 검증, CN/ID/Serial 바인딩, timestamp·nonce 기반 replay 방어, SHA-256 메시지 무결성 검증, rate-limit을 적용한 서버. |
| `dashboard.py` | 두 서버가 보내는 이벤트를 SSE(`/stream`)로 수집해 accepted/rejected 카운트를 실시간 시각화 (Flask). |
| `client_common.py` | mTLS 커넥션, OCPP 프레임 생성, hash 계산 등 클라이언트 공통 로직. |
| `run_all_attacks.py` | 아래 공격 시나리오를 순서대로 실행하는 데모 러너. |

## 공격 시나리오

| 클라이언트 | 공격 유형 | vulnerable_server | secure_server |
|---|---|---|---|
| `client_normal.py` | 정상 통신 | Accept | Accept |
| `tamper_attack_client.py` | 잘못된 seed로 메시지 해시 위조 | Accept | Reject (hash mismatch) |
| `spoof_serial_client.py` | 인증서 CN과 다른 serial 사칭 | Accept | Reject (id-binding mismatch) |
| `replay_attack_client.py` | 동일 요청(ts/nonce/hash) 재전송 | Accept | Reject (replay-nonce) |
| `bad_subprotocol_client.py` | 잘못된 WebSocket subprotocol로 연결 | 무응답/연결 유지 | 연결 즉시 종료 |
| `no_cert_client.py` | 클라이언트 인증서 없이 접속 | - | TLS handshake 단계에서 차단 |
| `flood_attack_client.py` | 짧은 간격으로 대량 요청 | 전부 처리 | 60초 내 60건 초과 시 rate-limit |

## 실행 방법

```bash
pip install -r requirements.txt

# 인증서/키 생성 (mTLS 테스트용, 최초 1회)
# ca.key/server.key/client.key 등은 로컬에서 직접 생성해서 사용하세요.

# 1) 대시보드
python dashboard.py            # http://localhost:5001

# 2) 서버 (각각 다른 터미널)
python secure_server.py        # wss://localhost:8765
python vulnerable_server.py    # wss://localhost:8766

# 3) 공격 시나리오 실행
python run_all_attacks.py
```

## 기술 스택

Python · `python-ocpp` · `websockets` (mTLS) · Flask (SSE 대시보드) · SHA-256 메시지 무결성 검증

## 보안 참고

`ca.key` / `server.key` / `client.key` 등 개인키 파일은 저장소에 포함하지 않습니다.
로컬에서 직접 CA/서버/클라이언트 인증서를 생성해 테스트하세요.
