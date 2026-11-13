# Assignment A solution

From the repository root (Python 3.11+):

```bash
python -m pip install -r requirements.txt
python assignment-a-data/tools/generate_data.py --seed 42 --scale small --out data
# PowerShell: generate a fresh secret and never commit it.
$env:LEDGER_ENCRYPTION_KEY = python -c "import secrets; print(secrets.token_urlsafe(32))"
python solution/main.py --db solution/ledger.sqlite3 ingest data/drop_1
python solution/main.py --db solution/ledger.sqlite3 ingest data/drop_2
python solution/main.py --db solution/ledger.sqlite3 report --out reports
python -m pytest -q solution/test_ledger.py
```

The SQLite file is the durable source of truth. Re-running an ingested source
file changes nothing. `LEDGER_ENCRYPTION_KEY` (or `--key`) is required: it derives
independent AES-GCM encryption and HMAC phone-matching keys. Never commit it.

## Design at a glance

`leads` contains one canonical valid lead per workflow and tokenised phone; its
first valid upload fixes the lead's batch. `ledger_events` is append-only and
deduplicated by event ID. `event_quarantine` explicitly shows valid ledger
events that cannot currently be linked to a lead. Reports derive from the
ledger and current leads, so a late-arriving lead automatically reconciles an
older quarantined event without modifying history.

PII is protected before persistence: phone values become HMAC tokens (plus the
required final four digits for masking) and customer names are AES-GCM
encrypted. Raw CSV rows and raw event JSON are not stored.

Lead file delivery is checkpointed by absolute source path and streamed
SHA-256 digest. This makes reruns safe for all counters, rejections, and lead
merges—not merely event rows. See [INTERVIEW_GUIDE.md](INTERVIEW_GUIDE.md) for
the full schema, rule-by-rule flow, and design trade-offs.

## Validation performed

The suite contains 12 focused tests covering validation and aliases, blank rows,
defaults and merging, source-file idempotency, cross-drop event duplicates,
late-lead quarantine reconciliation, dispositions/overrides, IST grouping,
success-lead deduplication, AES-GCM tamper detection, and plaintext-PII checks.

The seed-42 small generator run was also verified end-to-end: both drops ingested,
all five reports generated, then both drops ingested again with unchanged output.

## Output

`report --out reports` writes `batch_summary.csv`, `daily_overview.csv`,
`lead_report.csv`, `rejections.csv`, and `data_quality.json`. Existing output
files are replaced deterministically; the SQLite database remains the source
of truth.
