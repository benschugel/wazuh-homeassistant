"""End-to-end tests for custom-homeassistant.py.

Starts a local webhook sink, runs the script the way Wazuh does (one process
per alert) and checks what reaches the sink. Standard library only.

    python tests/run_tests.py            # uses the current interpreter
    python tests/run_tests.py /path/to/python3

The second form runs the script with another interpreter, for example
Wazuh's bundled one inside the manager container.
"""
import http.server
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import threading
import time

ROOT = pathlib.Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "integrations" / "custom-homeassistant.py"
SAMPLES = ROOT / "tests" / "samples"
PYTHON = sys.argv[1] if len(sys.argv) > 1 else sys.executable

received = []


class Sink(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        received.append(json.loads(body))
        self.send_response(200)
        self.end_headers()

    def log_message(self, *a):
        pass


server = http.server.HTTPServer(("127.0.0.1", 0), Sink)
threading.Thread(target=server.serve_forever, daemon=True).start()
HOOK = "http://127.0.0.1:%d/api/webhook/test" % server.server_port

tmp = pathlib.Path(tempfile.mkdtemp(prefix="wazuh-ha-"))
env = dict(os.environ, WAZUH_HA_CONFIG=str(tmp / "config.json"), WAZUH_HA_LOG_FILE=str(tmp / "log"),
           WAZUH_HA_STATE_FILE=str(tmp / "state"))
failures = []


def configure(**cfg):
    (tmp / "config.json").write_text(json.dumps(cfg))


def reset_state():
    for n in ("state", "log"):
        try:
            (tmp / n).unlink()
        except FileNotFoundError:
            pass


def run(sample, alert_override=None):
    path = SAMPLES / sample
    if alert_override:
        alert = json.loads(path.read_text())
        alert.update(alert_override)
        path = tmp / "alert.json"
        path.write_text(json.dumps(alert))
    r = subprocess.run([PYTHON, str(SCRIPT), str(path), "", HOOK], env=env, capture_output=True, text=True)
    return r.returncode


def log_lines():
    try:
        return (tmp / "log").read_text().splitlines()
    except FileNotFoundError:
        return []


def check(name, cond, detail=""):
    print("%-4s %s %s" % ("ok" if cond else "FAIL", name, detail if not cond else ""))
    if not cond:
        failures.append(name)


# 1. A normal high alert is sent with an enriched payload.
configure(cooldown_seconds=0, burst_max=0)
reset_state(); received.clear()
rc = run("sysmon_exe_dropped_level15.json")
check("level 15 alert is sent", rc == 0 and len(received) == 1, "rc=%s received=%d log=%s" % (rc, len(received), log_lines()))
if received:
    p = received[0]
    check("payload keeps title/message", p["title"].startswith("Wazuh level 15") and "rule 92213" in p["message"])
    check("payload has severity word", p["severity"] == "critical", p.get("severity"))
    check("payload has MITRE ids", p["mitre_ids"] == ["T1036"] or p["mitre_ids"], p.get("mitre_ids"))
    check("payload has process and file", p["process"] and p["file"], (p.get("process"), p.get("file")))
    check("payload has no dashboard link by default", "dashboard_url" not in p)

# 2. Group filter drops vulnerability alerts.
reset_state(); received.clear()
rc = run("vulnerability_level13.json")
check("vulnerability alert is skipped", rc == 0 and not received and any("group filter" in l for l in log_lines()), log_lines())

# 3. Dashboard link template.
configure(cooldown_seconds=0, burst_max=0, dashboard_url="https://wazuh.lan/x?q={alert_id}&a={agent_id}")
reset_state(); received.clear()
run("unifi_honeypot_level10.json")
check("dashboard link rendered", received and received[0].get("dashboard_url", "").startswith("https://wazuh.lan/x?q=") and "&a=000" in received[0]["dashboard_url"], received and received[0].get("dashboard_url"))
check("unifi payload has srcmac and empty srcip is null", received and received[0]["srcmac"] and received[0]["srcip"] is None, received and (received[0].get("srcmac"), received[0].get("srcip")))

# 4. Cooldown: same rule and agent twice within the window sends once.
configure(cooldown_seconds=300, burst_max=0)
reset_state(); received.clear()
run("sysmon_exe_dropped_level15.json"); run("sysmon_exe_dropped_level15.json")
check("cooldown suppresses the repeat", len(received) == 1 and any("cooldown" in l for l in log_lines()), (len(received), log_lines()))
# A different rule on the same agent is not affected.
run("unifi_honeypot_level10.json")
check("cooldown is per rule and agent", len(received) == 2, len(received))

# 5. Burst: more than burst_max distinct alerts in the window -> one summary, then silence.
configure(cooldown_seconds=0, burst_window_seconds=60, burst_max=3)
reset_state(); received.clear()
for i in range(8):
    run("sysmon_exe_dropped_level15.json", {"id": "burst-%d" % i, "rule": dict(json.loads((SAMPLES / "sysmon_exe_dropped_level15.json").read_text())["rule"], id=str(900000 + i))})
check("burst sends 3 alerts plus one summary", len(received) == 4, len(received))
check("4th message is the burst summary", len(received) == 4 and received[3]["burst"] and received[3]["title"] == "Wazuh: alert burst", received[3:] and received[3].get("title"))
check("remaining alerts were held", sum("burst hold" in l for l in log_lines()) == 4, log_lines())

# 6. After the burst window, the next alert reports how many were held.
state = json.loads((tmp / "state").read_text())
state["burst_until"] = 0
state["sent_times"] = []
(tmp / "state").write_text(json.dumps(state))
run("unifi_honeypot_level10.json")
check("next alert carries suppressed count", len(received) == 5 and received[4]["suppressed_since_last"] == 4, received[4:] and received[4].get("suppressed_since_last"))

# 7. Bad input handling.
rc = run("does-not-exist.json")
check("missing alert file exits 6", rc == 6, rc)
(tmp / "bad.json").write_text("{not json")
rc = subprocess.run([PYTHON, str(SCRIPT), str(tmp / "bad.json"), "", HOOK], env=env, capture_output=True).returncode
check("invalid JSON exits 7", rc == 7, rc)
rc = subprocess.run([PYTHON, str(SCRIPT), str(tmp / "bad.json")], env=env, capture_output=True).returncode
check("missing arguments exits 2", rc == 2, rc)

# 8. Unknown config keys are ignored, not fatal.
(tmp / "config.json").write_text(json.dumps({"cooldown_seconds": 0, "burst_max": 0, "bogus": 1}))
reset_state(); received.clear()
rc = run("unifi_honeypot_level10.json")
check("unknown config key is ignored", rc == 0 and len(received) == 1 and any("unknown keys" in l for l in log_lines()), log_lines())

# 9. The webhook URL never appears in the log.
check("hook URL absent from log", not any(HOOK in l for l in log_lines()))

server.shutdown()
print("\n%d checks failed" % len(failures))
sys.exit(1 if failures else 0)
