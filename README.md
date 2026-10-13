# SOC Detection Engineering Benchmark

A containerized security monitoring lab built to evaluate detection rules against simulated attack behaviors mapped to MITRE ATT&CK. In its current state it measures whether log evidence of each attack reaches Elasticsearch; no detection rule is executed.

## Current Status

**Log evidence observed: 2 of 11 planned techniques, one run each**

| Technique | Status | Log-availability latency | Evidence |
|-----------|--------|--------------------------|----------|
| T1136.001 (Local Account) | Observed (1 run) | 3.20s | `results/validation_20261010_125751.json` |
| T1053.003 (Cron) | Observed (1 run, 65s window) | 30.94s | `results/t1053003_65s_window_20261010_140043.json` |
| 9 others | Not evaluated | - | auditd, their expected log source, did not run in the target container |

**Terminology** (matches `paper/draft_revised_phase2.tex`):

- **Observed** means at least one indexed log document matched the technique's keywords inside its collection window. It is not a confirmed detection: no detection rule ran and no alert was raised. The evidence files record this outcome as `"result": "DETECTED"`.
- **Log-availability latency** is the `@timestamp` of the first matching document (assigned by Filebeat when it reads the log line) minus the attack start time (taken from the harness clock on the host). Earlier versions called this "TTD"; the code and evidence files still name the field `mean_time_to_detect_seconds`. The two clocks were not compared.
- **Not evaluated** means the technique was executed only in four early full-manifest runs, which reported 0 of 12 tests observed before the harness was corrected, and was not run again.

**Matching method:** Keyword-based Elasticsearch queries (not Sigma rule evaluation). The Sigma files in `rules/sigma/` are not loaded by the harness.

## Quick Start

```bash
# Install dependencies, including pytest (equivalent: make install)
pip install -e ".[dev]"

# Start the lab (alternative from the repository root: make up)
cd docker && docker-compose up -d

# Enable cron telemetry (for T1053.003)
docker exec soc-target bash -c '
  sed -i "s/^#cron\.\*/cron.*/" /etc/rsyslog.d/50-default.conf
  pkill -x rsyslogd; sleep 1; rsyslogd
  service cron start'

# Run tests
python -m pytest tests/ -v

# Execute single technique
python -c "
from benchmark.runner import AttackRunner
runner = AttackRunner()
results = runner.run_single_technique('T1136.001')
print(f'Success: {results[0].success}')
"
```

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                      Docker Compose Stack                        │
├─────────────────┬─────────────────┬─────────────────────────────┤
│  Attack Target  │   Log Pipeline  │      Detection Engine       │
│  (Ubuntu 22.04) │   (Filebeat)    │  (Elasticsearch + Keywords) │
└─────────────────┴─────────────────┴─────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Benchmark Harness (Python)                    │
│  - Run attack commands     - Collect detection results          │
│  - Measure detection rate  - Generate reports                   │
└─────────────────────────────────────────────────────────────────┘
```

## Techniques

| ID | Technique | Telemetry | Status |
|----|-----------|-----------|--------|
| T1136.001 | Local Account | auth.log | Observed (1 run) |
| T1053.003 | Cron | cron.log | Observed (1 run, 65s window) |
| T1059.004 | Unix Shell | auditd (not running) | Not evaluated |
| T1548.001 | Setuid/Setgid | auditd (not running) | Not evaluated |
| T1070.004 | File Deletion | auditd (not running) | Not evaluated |
| T1070.003 | Clear History | auditd (not running) | Not evaluated |
| T1027 | Obfuscated Files | auditd (not running) | Not evaluated |
| T1018 | Remote Discovery | auditd (not running) | Not evaluated |
| T1082 | System Info | auditd (not running) | Not evaluated |
| T1105 | Tool Transfer | auditd (not running) | Not evaluated |
| T1571 | Non-Std Port | auditd (not running) | Not evaluated |

## Metrics

| Metric | Description |
|--------|-------------|
| **Observed** | Whether at least one log document matched the technique's keywords inside the collection window (code field: `detection_rate`, tests observed / tests executed) |
| **Log-availability latency** | `@timestamp` of the first matching document minus attack start time (code field: `mean_time_to_detect_seconds`) |
| **Collection Window** | Time range searched for matching documents: 1s before the attack starts to 15s after it ends (65s for T1053.003) |

**Note:** False positive rate requires a baseline workload run, which was not performed. Generated reports print `0.0/hour` in that case; read it as "not measured". Each reported result is a single observation, so no rates or averages across runs are available.

## Key Findings

1. **Technique-specific timing matters:** T1053.003 (Cron) was missed with a 15-second post-attack window and observed with a 65-second one, because cron checks for crontab changes once per minute.

2. **auditd did not run in this lab:** The attack manifest names auditd as the expected log source for all 11 techniques. The audit daemon did not run in the target container, and `auditctl -s` returns "Operation not permitted" even though the container is privileged. We attribute this to the Linux kernel accepting audit control only from the initial PID namespace; the container has its own. This is a property of this Compose configuration, not of Docker in general. Sharing the host PID namespace was not tested.

3. **Interpreting the latencies:** T1136.001's 3.20s covers log writing, Filebeat pickup, and indexing. T1053.003's 30.94s is mostly the wait for cron's next minute check (the attack ran 33s into the minute), so it depends on when the command happened to start.

4. **Cron attribution caveat:** The matched cron event is a generic `RELOAD (/etc/crontab)` line. The harness ran the cleanup edit immediately after the attack, so the match cannot be tied to the malicious entry. The recorded match count of 2 is the same line indexed from both `syslog` and `cron.log`.

## Project Structure

```
soc-detection-benchmark/
├── docker/                 # Docker infrastructure
│   ├── docker-compose.yml
│   ├── target/            # Ubuntu target container
│   └── filebeat/          # Log shipping config
├── attacks/
│   └── attack_manifest.yaml   # 11 ATT&CK techniques
├── benchmark/             # Python harness
│   ├── runner.py          # Attack execution
│   ├── collector.py       # Alert collection
│   ├── metrics.py         # Detection metrics
│   └── report.py          # Report generation
├── results/               # Evidence files
├── paper/                 # LaTeX drafts
├── tests/                 # 60 automated tests
└── pyproject.toml
```

## Tests

```bash
# Run all tests
python -m pytest tests/ -v

# Run specific test module
python -m pytest tests/test_detection.py -v
```

**60 tests**, all run without network access: Elasticsearch responses are mocked, and the rest exercise pure harness logic. They check the harness code only. Passing tests do not show that log evidence appears in the live lab or that any detection works end to end.

They cover:
- Timestamp handling and UTC conversion
- Collection window buffers (default 15s, cron 65s)
- Detection key matching
- Metrics calculation
- Attack result serialization

## Limitations

- **No auditd:** The audit daemon did not run in the target container (see Key Findings), so 9 of 11 planned techniques were not evaluated
- **Keyword matching:** Not a Sigma rule evaluation
- **No FP baseline:** False positive rate not measured
- **Single observations:** Each technique was observed in one run; runs were not repeated
- **Manual cron setup:** Requires runtime configuration
- **Linux only:** No Windows coverage

## Extending

### Add a technique

1. Add to `attacks/attack_manifest.yaml`
2. Add detection keys to `benchmark/metrics.py:TECHNIQUE_DETECTION_KEYS`
3. Add buffer override to `TECHNIQUE_POST_BUFFER` if needed
4. Test with `runner.run_single_technique()`

### Full benchmark on VM

auditd needs an environment where the audit daemon can register with the kernel, for example a VM. This was not tested.

## License

MIT
