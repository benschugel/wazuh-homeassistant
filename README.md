# Wazuh to Home Assistant

Send Wazuh alerts to your phone through Home Assistant, without the flood.

> **Status: work in progress.** The integration script runs in my homelab and
> has tests. The Home Assistant package is a reference and is not what I run
> today, so expect it to change. Payload fields and settings may still shift.
> WIP until the package is what I run and the payload is frozen.

Wazuh ships integrations for Slack, PagerDuty and Shuffle. This is the same
idea for Home Assistant: a manager-side integration script that posts to a
webhook, and a Home Assistant package that turns the post into a phone
notification, an event other automations can use, and a few sensors.

Two things make it usable day to day:

- **Deduplication.** The same rule on the same agent notifies once per
  cooldown window. When many different alerts land inside a short window,
  one summary goes out and the rest are held, then counted on the next
  notification. A browser update that produces 24 CVE alerts in one second
  becomes zero notifications, and a scan that trips 30 rules becomes one.
- **Group filter.** Rule groups such as `vulnerability-detector` never notify,
  whatever their level. Findings stay in the Wazuh dashboard.

The script uses only the Python standard library, so it runs on the
interpreter Wazuh bundles. Nothing is sent anywhere except your webhook URL,
and the URL is never written to the log.

## Layout

| Path | Purpose |
|------|---------|
| `integrations/custom-homeassistant.py` | The integration script. |
| `integrations/custom-homeassistant` | Wazuh's standard launcher, copied unchanged. |
| `integrations/custom-homeassistant.json.example` | All settings with their defaults. |
| `homeassistant/wazuh.yaml` | Home Assistant package: webhook automation, event, sensors. |
| `tests/run_tests.py` | End-to-end tests with a local webhook sink and sample alerts. |

## Install

### 1. Home Assistant

Copy `homeassistant/wazuh.yaml` to `<config>/packages/wazuh.yaml`. If you do
not use packages yet, add to `configuration.yaml`:

```yaml
homeassistant:
  packages: !include_dir_named packages
```

Edit the two placeholders in the file:

- `REPLACE_WEBHOOK_ID`: a long random string. Generate one with
  `openssl rand -hex 24`. It is the only thing protecting the endpoint, so
  keep `local_only: true` unless the manager is off your LAN.
- `notify.REPLACE_PHONE`: your mobile app notify service, for example
  `notify.mobile_app_pixel_9`. Find it under Developer tools, Actions.

Restart Home Assistant or reload automations and template entities.

### 2. Wazuh manager

Copy both files from `integrations/` to `/var/ossec/integrations/` on the
manager, owned by `root:wazuh` with mode `750`. Optionally copy the example
config to `/var/ossec/integrations/custom-homeassistant.json` and adjust it.

Add to `ossec.conf`:

```xml
<integration>
  <name>custom-homeassistant</name>
  <hook_url>http://HA_HOST:8123/api/webhook/REPLACE_WEBHOOK_ID</hook_url>
  <level>10</level>
  <alert_format>json</alert_format>
</integration>
```

`<level>` is the floor: Wazuh only runs the script for alerts at or above it.
Then restart the manager (`wazuh-control restart`).

In the Wazuh Docker images the integrations folder is a named volume, so the
files survive a container restart. The `ossec.conf` bind mount is copied in on
the container's first start only, so edit the live file as well.

### 3. Check it

```
tail -f /var/ossec/logs/integrations.log
```

Each alert the script sees is logged as sent, or skipped with the reason
(`group filter`, `cooldown`, `burst hold`). Nothing in the log means Wazuh
did not call the script: check the `<level>` and that the integration block
is inside `<ossec_config>`.

## Settings

`custom-homeassistant.json`, next to the script. Every key is optional.

| Key | Default | Meaning |
|-----|---------|---------|
| `skip_groups` | `["vulnerability-detector"]` | Rule groups that never notify. |
| `only_groups` | `[]` | If set, only these groups notify. |
| `skip_agents` | `[]` | Agent names or ids that never notify. |
| `cooldown_seconds` | `300` | Same rule and agent notifies once per window. `0` disables. |
| `burst_window_seconds` | `60` | Window for burst detection. |
| `burst_max` | `5` | Notifications allowed inside the window before a summary is sent and the rest held. `0` disables. |
| `dashboard_url` | `""` | Link template with `{alert_id}`, `{rule_id}`, `{agent_id}`, `{agent_name}`. |
| `timeout_seconds` | `10` | Webhook HTTP timeout. |

State for cooldown and burst tracking lives in
`/var/ossec/var/run/custom-homeassistant.state`, written under a file lock
because Wazuh may run several copies of the script at once.

## Payload

Everything is flat so templates stay short. Fields that do not apply to an
alert are `null`.

```json
{
  "title": "Wazuh level 15: WORKSTATION-01",
  "message": "Executable file dropped in folder commonly used by malware (rule 92213)",
  "level": 15, "severity": "critical",
  "rule_id": "92213", "description": "...", "groups": ["sysmon_event_11", "..."],
  "agent": "WORKSTATION-01", "agent_id": "001", "agent_ip": "192.0.2.10",
  "mitre_ids": ["T1036"], "mitre_tactics": ["Defense Evasion"], "mitre_techniques": ["Masquerading"],
  "srcip": null, "dstip": null, "srcmac": null, "user": "...", "process": "C:\\...\\msedgewebview2.exe",
  "command_line": null, "file": "C:\\Users\\...\\Temp\\...\\x.dll", "cve": null, "package": null,
  "timestamp": "2026-10-06T07:34:51.000+0000", "alert_id": "1759736091.1234",
  "suppressed_since_last": 0, "burst": false,
  "dashboard_url": "https://..."
}
```

`title` and `message` are what a minimal automation needs. `severity` follows
the Wazuh dashboard bands: low 0 to 6, medium 7 to 11, high 12 to 14,
critical 15.

## Home Assistant side

The package gives you:

- **`wazuh_alert` event** with the full payload, so other automations can
  react (flash a light on critical, speak on a satellite) without touching
  the webhook.
- **Phone notification** with the alert, a one-line summary of process, file,
  source IP, user and MITRE technique, an "Open Wazuh" button when a
  dashboard link is configured, and an "Acknowledge" button. Level 12 and
  above and burst summaries use a separate high-importance channel so you can
  let them through Do Not Disturb on Android.
- **`sensor.wazuh_last_alert`** with the payload as attributes.
- **`sensor.wazuh_alerts_today`** and **`sensor.wazuh_suppressed_today`**,
  reset at midnight.

## Tests

```
python tests/run_tests.py
```

Runs the script against the anonymised alerts in `tests/samples/` through a
local webhook sink and checks sending, filtering, cooldown, burst handling,
error exits and that the hook URL never reaches the log. To run with the
interpreter Wazuh uses, copy the repo into the manager container and pass its
Python:

```
docker cp . wazuh.manager:/tmp/wh
docker exec wazuh.manager /var/ossec/framework/python/bin/python3 /tmp/wh/tests/run_tests.py /var/ossec/framework/python/bin/python3
```

## License

BSD 3-Clause. The launcher script `integrations/custom-homeassistant` is Wazuh's and
stays under GPLv2.
