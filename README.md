# WebSphere ND 8.5.5 — Configuration Drift Detection

Automated baseline extraction and hourly drift monitoring for a WebSphere ND
cell with one DMGR and a cluster spread across 6 nodes.

---

## Architecture

```
DMGR (source of truth)
  │
  ├── DMGR config repository  (profiles/Dmgr01/config/cells/…)
  │     └── includes all resources.xml files
  └── wsadmin live dump  (server attrs, JVM, thread pools, datasources…)

                    ▼  extract_baseline.sh  (run once)
              /opt/was-drift/baseline/
                    ├── config_repo/          ← full copy of DMGR config tree
                    ├── resources_xml/        ← all resources.xml, path-preserved
                    ├── wsadmin_dump/         ← live attribute dumps per object type
                    └── checksums.sha256      ← SHA-256 of every captured file

                    ▼  check_drift.sh  (cron every 60 min)
              /opt/was-drift/snapshot/        ← same structure, current state
              /opt/was-drift/reports/
                    ├── drift_report_<ts>.json
                    └── resources_drift_<ts>.txt

                    ▼  drift_email.py  (called by check_drift.sh when drift found)
              HTML + plain-text email  →  was-alerts@yourcompany.com
```

---

## Files

| File | Purpose |
|---|---|
| `extract_baseline.sh` | Run **once** to capture the authoritative baseline |
| `check_drift.sh` | Run by cron every 60 min; exits 0 (no drift) or 1 (drift) |
| `drift_email.py` | Sends rich HTML drift-alert email |
| `install.sh` | Deploys scripts + registers cron |

---

## What is captured

### File-based (config repository)
Everything under `$DMGR_PROFILE/config/` is snapshotted verbatim, including:

- `cell.xml` — cell-level settings
- `security.xml` — global security configuration  
- `variables.xml` — WebSphere substitution variables
- `virtualhosts.xml` — virtual host definitions
- `applications/` — deployed application descriptors
- `nodes/<node>/servers/<server>/server.xml` — per-server config
- **`resources.xml`** — JDBC providers, datasources, JMS, mail sessions (at every scope: cell, node, cluster, server). Every `resources.xml` is **also** extracted into a separate `resources_xml/` tree for targeted diffing.

### wsadmin live attribute dumps
Using `AdminConfig.show()` for each object:

| Object type | Coverage |
|---|---|
| ServerCluster + ClusterMembers | Cluster-level attributes |
| Server | All application servers (excludes dmgr/nodeagent) |
| JavaVirtualMachine | Heap, JVM args, generic JVM args |
| ThreadPool | WebContainer, ORB, SIB thread pools |
| TransactionService | TX timeout, max in-flight TXs |
| DataSource | JNDI name, connection pool, auth alias |
| J2EEResourceProperty | DataSource connection properties |
| JDBCProvider | Driver class, classpath |
| VirtualHost + HostAlias | Port/hostname mappings |
| Security | Global security settings |
| ApplicationDeployment | Deployed application metadata |
| VariableSubstitutionEntry | All WAS variables |
| Library | Shared library definitions |

---

## Installation

### Prerequisites
- Python 3.x on the DMGR OS (standard library only — no pip installs needed)
- DMGR running and accessible via SOAP
- OS user that can read `$DMGR_PROFILE/config/` and run `wsadmin.sh`
- SMTP relay reachable from the DMGR host

### Steps

```bash
# 1. Copy scripts to the DMGR host
scp extract_baseline.sh check_drift.sh drift_email.py install.sh \
    wasadmin@dmgr-host:/tmp/was-drift/

# 2. SSH to DMGR host
ssh wasadmin@dmgr-host
cd /tmp/was-drift

# 3. Edit configuration variables in the scripts
vi extract_baseline.sh   # set WAS_HOME, DMGR_PROFILE, DMGR_HOST, etc.
vi check_drift.sh        # same variables + EMAIL_TO, SMTP_HOST

# 4. Run installer (as root or user with crontab access)
sudo bash install.sh

# 5. Extract initial baseline
sudo -u wasadmin /opt/was-drift/extract_baseline.sh

# 6. Smoke-test the drift check (should report no drift)
sudo -u wasadmin /opt/was-drift/check_drift.sh
echo "Exit code: $?"
```

---

## Configuration variables

### Common to both shell scripts

| Variable | Description | Example |
|---|---|---|
| `WAS_HOME` | WAS install root | `/opt/IBM/WebSphere/AppServer` |
| `DMGR_PROFILE` | DMGR profile path | `…/profiles/Dmgr01` |
| `DMGR_HOST` | DMGR hostname (SOAP) | `dmgr01.internal` |
| `DMGR_PORT` | DMGR SOAP port | `8879` |
| `WAS_USER` | WAS admin username | `wasadmin` |
| `WAS_PASS` | WAS admin password | `secret` |
| `CELL_NAME` | Cell name (display only) | `ProdCell01` |
| `CLUSTER_NAME` | Cluster name (display only) | `AppCluster` |
| `DRIFT_HOME` | Tool working directory | `/opt/was-drift` |

### `check_drift.sh` only

| Variable | Description |
|---|---|
| `EMAIL_TO` | Comma-separated alert recipients |
| `EMAIL_FROM` | Sender address |
| `SMTP_HOST` | SMTP relay hostname |
| `SMTP_PORT` | SMTP relay port (default 25) |

### SMTP authentication (optional)
Set environment variables before running or in the cron environment:
```bash
export DRIFT_SMTP_USER="smtpuser"
export DRIFT_SMTP_PASS="smtppass"
```

---

## Resetting the baseline

After a planned change (patching, intentional config update), reset the baseline
so the next drift check is clean:

```bash
/opt/was-drift/extract_baseline.sh
```

**Best practice:** run this immediately after every approved change window so
the baseline always reflects the known-good state.

---

## Cron schedule

Installed as: `0 * * * *` (top of every hour).

To change to every 30 minutes: `*/30 * * * *`  
To change to every 2 hours: `0 */2 * * *`

Edit with: `crontab -u wasadmin -e`

---

## Report files

```
/opt/was-drift/reports/
  drift_report_<YYYYMMDD_HHMMSS>.json      ← machine-readable full report
  resources_drift_<YYYYMMDD_HHMMSS>.txt    ← resources.xml specific diffs

/opt/was-drift/logs/
  check_drift_<YYYYMMDD_HHMMSS>.log        ← per-run log
  extract_baseline_<YYYYMMDD_HHMMSS>.log   ← baseline extraction log
  cron.log                                  ← cron stdout/stderr
```

Reports and logs older than 30 days are automatically purged.

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `wsadmin dump failed` in log | Wrong DMGR host/port/credentials | Check `DMGR_HOST`, `DMGR_PORT`, `WAS_USER`, `WAS_PASS` |
| Email not received | SMTP not reachable | Verify `SMTP_HOST`/`SMTP_PORT`; check firewall |
| Constant drift on wsadmin_dump files | Timestamps in WAS output | Normal — file-based comparison is authoritative |
| `Baseline directory not found` | Baseline not extracted yet | Run `extract_baseline.sh` |
| False positives on temp/work dirs | WAS writes transient files | Add exclusion patterns to `find` in `check_drift.sh` |

### Adding file exclusions
To ignore specific paths (e.g. `wstemp`, `workspace`), add `-not -path "*/wstemp/*"` to
the `find` commands in both `extract_baseline.sh` and `check_drift.sh`.

---

## Security notes

- Store `WAS_PASS` in a restricted file (chmod 600) and `source` it rather than
  hard-coding it in the script, or use WebSphere's soap.client.props mechanism.
- `DRIFT_HOME/baseline/` should be readable only by the drift monitor user.
- The JSON reports contain configuration details — restrict `DRIFT_HOME/reports/`.
