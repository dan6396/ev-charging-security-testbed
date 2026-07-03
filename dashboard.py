# dashboard.py
from flask import Flask, render_template, request, Response
import json
import time
import queue
import threading
import logging

app = Flask(__name__)
events_q = queue.Queue()

# 서버별 accepted / rejected 카운트
counters = {
    "vulnerable": {"accepted": 0, "rejected": 0},
    "secure": {"accepted": 0, "rejected": 0},
}

_lock = threading.Lock()
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/events", methods=["POST"])
def ingest_event():
    try:
        ev = request.get_json() or {}
    except Exception:
        ev = {}

    server = ev.get("server", "")
    result = str(ev.get("result", "")).lower()

    # 서버 / 결과 필터링
    if server not in ("secure", "vulnerable"):
        # low-level, unknown 등은 아예 무시
        return ("", 204)

    if result not in ("accepted", "rejected"):
        # accepted / rejected 가 아니면 무시
        return ("", 204)

    # timestamp 보정
    ev["ts"] = ev.get("ts", time.time())

    # 카운터 업데이트
    with _lock:
        counters[server][result] += 1

    # 이벤트 스트림용 큐에 push
    events_q.put(ev)
    return ("", 204)


def event_stream():
    while True:
        ev = events_q.get()
        with _lock:
            snapshot = json.loads(json.dumps(counters))

        data = {
            "event": ev,
            "counters": snapshot,
        }
        yield f"data: {json.dumps(data)}\n\n"


@app.route("/stream")
def stream():
    return Response(event_stream(), mimetype="text/event-stream")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001, debug=False, threaded=True)
