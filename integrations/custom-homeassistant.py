#!/var/ossec/framework/python/bin/python3
"""Wazuh integration: forward alerts to a Home Assistant webhook.

Wazuh runs this once per alert as the ``wazuh`` user with three arguments:
the alert file, the ``<api_key>`` value (unused here) and the ``<hook_url>``.

    <integration>
      <name>custom-homeassistant</name>
      <hook_url>http://HA_HOST:8123/api/webhook/WEBHOOK_ID</hook_url>
      <level>10</level>
      <alert_format>json</alert_format>
    </integration>

Optional settings live in ``custom-homeassistant.json`` next to this file.
See ``custom-homeassistant.json.example`` for every key and its default.

What the script adds on top of Wazuh's own level filter:

* group filter      - never notify for some rule groups (vulnerability scans).
* cooldown          - the same rule on the same agent notifies once per window.
* burst protection  - when many alerts arrive within a short window, one
                      summary goes out and the rest are held until it ends.
* a flat payload    - level, severity word, agent, MITRE, source IP, process,
                      file, CVE and a dashboard link, ready for an automation.

Standard library only. Nothing but the webhook URL leaves the host, and the
URL is never written to the log.
"""
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

try:
    import fcntl
except ImportError:  # Windows, for running the tests locally. The manager is Linux.
    fcntl = None

# Exit codes, matching Wazuh's bundled integrations.
ERR_BAD_ARGUMENTS = 2
ERR_FILE_NOT_FOUND = 6
ERR_INVALID_JSON = 7

ALERT_INDEX = 1
WEBHOOK_INDEX = 3

HERE = os.path.dirname(os.path.realpath(__file__))
WAZUH_PATH = os.path.dirname(HERE)

CONFIG_FILE = os.environ.get("WAZUH_HA_CONFIG", os.path.join(HERE, "custom-homeassistant.json"))
LOG_FILE = os.environ.get("WAZUH_HA_LOG_FILE", os.path.join(WAZUH_PATH, "logs", "integrations.log"))
STATE_FILE = os.environ.get("WAZUH_HA_STATE_FILE", os.path.join(WAZUH_PATH, "var", "run", "custom-homeassistant.state"))

DEFAULTS = {
    # Rule groups that never notify, whatever their level.
    "skip_groups": ["vulnerability-detector"],
    # If non-empty, only alerts in one of these groups notify.
    "only_groups": [],
    # Agents (names or ids) that never notify.
    "skip_agents": [],
    # Seconds before the same rule on the same agent may notify again. 0 disables.
    "cooldown_seconds": 300,
    # Burst protection: after `burst_max` notifications inside `burst_window_seconds`,
    # send one summary and hold further alerts until the window has passed.
    "burst_window_seconds": 60,
    "burst_max": 5,
    # Dashboard link template. Placeholders: {alert_id} {rule_id} {agent_id} {agent_name}
    # Empty string disables the link.
    "dashboard_url": "",
    # HTTP timeout for the webhook post.
    "timeout_seconds": 10,
}

SEVERITY = [(15, "critical"), (12, "high"), (7, "medium"), (0, "low")]


def log(msg):
    try:
        with open(LOG_FILE, "a") as f:
            f.write("custom-homeassistant: %s\n" % msg)
    except OSError:
        pass


def load_config():
    cfg = dict(DEFAULTS)
    try:
        with open(CONFIG_FILE) as f:
            user = json.load(f)
    except FileNotFoundError:
        return cfg
    except (OSError, json.JSONDecodeError) as e:
        log("config %s ignored: %s" % (CONFIG_FILE, e))
        return cfg
    unknown = sorted(set(user) - set(DEFAULTS))
    if unknown:
        log("config: unknown keys ignored: %s" % ", ".join(unknown))
    cfg.update({k: v for k, v in user.items() if k in DEFAULTS})
    return cfg


def load_alert(path):
    try:
        with open(path) as f:
            return json.load(f)
    except FileNotFoundError:
        log("alert file %s does not exist" % path)
        sys.exit(ERR_FILE_NOT_FOUND)
    except json.JSONDecodeError as e:
        log("failed parsing alert JSON: %s" % e)
        sys.exit(ERR_INVALID_JSON)


def severity(level):
    for floor, word in SEVERITY:
        if level >= floor:
            return word
    return "low"


def first(*values):
    for v in values:
        if v not in (None, "", "-"):
            return v
    return None


def build_payload(alert, cfg):
    rule = alert.get("rule", {})
    agent = alert.get("agent", {})
    data = alert.get("data", {})
    win = data.get("win", {}).get("eventdata", {})
    mitre = rule.get("mitre", {})
    level = int(rule.get("level", 0))
    description = rule.get("description", "N/A")
    agent_name = agent.get("name", "unknown")

    payload = {
        # Kept from the first version so existing automations keep working.
        "title": "Wazuh level %d: %s" % (level, agent_name),
        "message": "%s (rule %s)" % (description, rule.get("id", "?")),
        "level": level,
        "rule_id": rule.get("id"),
        "description": description,
        "agent": agent_name,
        "groups": rule.get("groups", []),
        "timestamp": alert.get("timestamp"),
        "alert_id": alert.get("id"),
        # Added in this version.
        "severity": severity(level),
        "agent_id": agent.get("id"),
        "agent_ip": agent.get("ip"),
        "mitre_ids": mitre.get("id", []),
        "mitre_tactics": mitre.get("tactic", []),
        "mitre_techniques": mitre.get("technique", []),
        "srcip": first(data.get("srcip"), win.get("sourceIp")),
        "dstip": first(data.get("dstip"), win.get("destinationIp")),
        "srcmac": first(data.get("srcmac")),
        "user": first(win.get("user"), win.get("targetUserName"), data.get("dstuser"), data.get("srcuser")),
        "process": first(win.get("image"), win.get("parentImage")),
        "command_line": first(win.get("commandLine")),
        "file": first(win.get("targetFilename"), alert.get("syscheck", {}).get("path"), data.get("file")),
        "cve": first(data.get("vulnerability", {}).get("cve")),
        "package": first(data.get("vulnerability", {}).get("package", {}).get("name")),
        "suppressed_since_last": 0,
        "burst": False,
    }
    if cfg["dashboard_url"]:
        try:
            payload["dashboard_url"] = cfg["dashboard_url"].format(
                alert_id=urllib.parse.quote(str(payload["alert_id"])),
                rule_id=payload["rule_id"], agent_id=payload["agent_id"],
                agent_name=urllib.parse.quote(agent_name))
        except (KeyError, IndexError) as e:
            log("dashboard_url template error: %s" % e)
    return payload


def group_filter(payload, cfg):
    """Return a reason string when the alert must not notify, else None."""
    groups = set(payload["groups"])
    if groups & set(cfg["skip_groups"]):
        return "group filter"
    if cfg["only_groups"] and not groups & set(cfg["only_groups"]):
        return "not in only_groups"
    if payload["agent"] in cfg["skip_agents"] or payload["agent_id"] in cfg["skip_agents"]:
        return "agent filter"
    return None


class State:
    """Small JSON state file with an exclusive lock, shared by concurrent runs."""

    def __init__(self, path):
        self.path = path
        self.data = {"last_sent": {}, "sent_times": [], "burst_until": 0, "suppressed": 0}
        self.fh = None

    def __enter__(self):
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        self.fh = open(self.path, "a+")
        if fcntl:
            fcntl.flock(self.fh, fcntl.LOCK_EX)
        self.fh.seek(0)
        raw = self.fh.read()
        if raw:
            try:
                self.data.update(json.loads(raw))
            except json.JSONDecodeError:
                log("state file was corrupt, starting fresh")
        return self

    def __exit__(self, *exc):
        self.fh.seek(0)
        self.fh.truncate()
        json.dump(self.data, self.fh)
        self.fh.flush()
        if fcntl:
            fcntl.flock(self.fh, fcntl.LOCK_UN)
        self.fh.close()


def decide(payload, cfg, state, now):
    """Apply cooldown and burst rules. Returns (send, reason)."""
    d = state.data
    key = "%s|%s" % (payload["rule_id"], payload["agent_id"])
    window = cfg["burst_window_seconds"]

    # Still inside a burst hold: count and drop.
    if now < d["burst_until"]:
        d["suppressed"] += 1
        return False, "burst hold"

    # Cooldown per rule and agent.
    cooldown = cfg["cooldown_seconds"]
    if cooldown and now - d["last_sent"].get(key, 0) < cooldown:
        d["suppressed"] += 1
        return False, "cooldown"

    # Burst detection on notifications actually sent.
    d["sent_times"] = [t for t in d["sent_times"] if now - t < window]
    if cfg["burst_max"] and len(d["sent_times"]) >= cfg["burst_max"]:
        d["burst_until"] = now + window
        d["suppressed"] += 1
        payload["burst"] = True
        payload["title"] = "Wazuh: alert burst"
        payload["message"] = ("%d notifications in %ds, holding further alerts for %ds. Latest: %s"
                              % (len(d["sent_times"]) + 1, window, window, payload["message"]))
        # The burst summary itself is sent.
        d["sent_times"].append(now)
        d["last_sent"][key] = now
        payload["suppressed_since_last"], d["suppressed"] = d["suppressed"], 0
        return True, "burst summary"

    d["sent_times"].append(now)
    d["last_sent"][key] = now
    # Forget cooldown entries older than an hour so the file stays small.
    d["last_sent"] = {k: t for k, t in d["last_sent"].items() if now - t < max(cooldown, 3600)}
    payload["suppressed_since_last"], d["suppressed"] = d["suppressed"], 0
    return True, "sent"


def post(url, payload, timeout):
    body = json.dumps(payload).encode()
    req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as res:
        return res.status


def main(args):
    if len(args) < 4:
        log("wrong arguments: %s" % args)
        sys.exit(ERR_BAD_ARGUMENTS)

    cfg = load_config()
    alert = load_alert(args[ALERT_INDEX])
    payload = build_payload(alert, cfg)
    tag = "rule %s level %s" % (payload["rule_id"], payload["level"])

    reason = group_filter(payload, cfg)
    if reason:
        log("%s skipped (%s)" % (tag, reason))
        return

    with State(STATE_FILE) as state:
        send, reason = decide(payload, cfg, state, time.time())
    if not send:
        log("%s skipped (%s)" % (tag, reason))
        return

    try:
        status = post(args[WEBHOOK_INDEX], payload, cfg["timeout_seconds"])
        log("%s %s, HTTP %s" % (tag, reason, status))
    except urllib.error.HTTPError as e:
        log("%s send failed: HTTP %s" % (tag, e.code))
        raise
    except (urllib.error.URLError, OSError) as e:
        log("%s send failed: %s" % (tag, type(e).__name__))
        raise


if __name__ == "__main__":
    main(sys.argv)
