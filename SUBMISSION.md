# Assignment A — Interaction Ledger & Reporting Pipeline

## 1. Summary

I implemented a Python 3.11+ pipeline that ingests lead CSV batches and call-event JSONL files, stores the resulting state in SQLite, and generates the five reports required by Assignment A.

The implementation is designed around two different kinds of data:

- **Leads** represent the current canonical record for a customer in a workflow. Lead uploads can be validated, deduplicated, and merged as new batches arrive.
- **Events** represent interaction history. They are stored in an append-only ledger so that original call and disposition events are retained, including when a supervisor later overrides a disposition.

The main design priorities were data correctness, deterministic processing, PII protection at rest, handling late-arriving events, and safe re-ingestion of previously processed files.

## 2. Repository layout and entry points

The solution code is in `solution/`:

- `solution/ledger.py` contains the ingestion, validation, persistence, event-linking, and reporting logic.
- `solution/main.py` provides the command-line interface.
- `solution/test_ledger.py` contains automated tests.

The workflow JSON schemas and disposition catalogue are read from `assignment-a-data/schemas/`. The supplied generator is used to create synthetic input data; generated data, SQLite databases, and secrets should not be committed.

## 3. Setup and execution

Python 3.11 or later is required. The implementation uses the `cryptography` package for AES-GCM and `pytest` to run the tests.

### Linux / macOS

From the repository root:

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install cryptography pytest

python assignment-a-data/tools/generate_data.py --seed 42 --scale small --out data

# Supply a fresh local secret. Do not commit it or place it in source control.
export LEDGER_ENCRYPTION_KEY="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"

python solution/main.py --db .local/ledger.sqlite3 ingest data/drop_1
python solution/main.py --db .local/ledger.sqlite3 ingest data/drop_2
python solution/main.py --db .local/ledger.sqlite3 report --out reports

pytest solution/test_ledger.py -q
```

### Windows PowerShell

From the repository root:

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install cryptography pytest

python assignment-a-data/tools/generate_data.py --seed 42 --scale small --out data

$env:LEDGER_ENCRYPTION_KEY = python -c "import secrets; print(secrets.token_urlsafe(32))"

python solution/main.py --db .local/ledger.sqlite3 ingest data/drop_1
python solution/main.py --db .local/ledger.sqlite3 ingest data/drop_2
python solution/main.py --db .local/ledger.sqlite3 report --out reports

pytest solution/test_ledger.py -q
```

The CLI accepts `--key` as an alternative to `LEDGER_ENCRYPTION_KEY`. The key must be supplied for both ingestion and reporting because the `Protector` is initialized whenever the ledger is opened. Keep the same key for the lifetime of a database; changing it would change phone tokens and make existing records difficult to match.

The commands above use `.local/` for the database so that the generated database is separate from source code. Ensure generated directories and local secrets are excluded from version control.

## 4. Architecture and data model

The pipeline has two ingestion paths that write to one SQLite database.

### 4.1 Lead ingestion

For each CSV under `leads/<workflow_id>/`, the workflow ID is taken from the directory structure and the corresponding JSON schema is loaded. Headers are normalized by trimming, lowercasing, and replacing runs of underscores or whitespace with one space. Canonical field names and schema aliases are mapped to the same field. Unrecognized columns are ignored.

Blank rows are skipped. Non-blank rows are numbered from one, excluding the header. Values are trimmed and validated in schema field order:

- `string`: stored as the trimmed string.
- `phone`: punctuation and other non-digits are removed, supported `91` and leading `0` prefixes are handled, and valid Indian mobile numbers are stored in canonical `+91XXXXXXXXXX` form before tokenization.
- `date`: the specified ISO, day-first slash, day-first hyphen, and day-month-name formats are parsed and stored as ISO dates.
- `decimal`: supported currency prefixes and thousands separators are removed; non-negative values are parsed with `Decimal` and rounded to two decimal places using `ROUND_HALF_UP`.
- `enum`: values are compared case-insensitively and stored in lowercase.

A missing required field or invalid phone rejects the row with the first failure in schema order. A present but invalid optional field is stored as `NULL` and contributes one warning, but warnings are counted only for rows that are accepted. Rejection records contain workflow, batch, row number, and reason, not customer PII.

Lead identity is `(workflow_id, phone_token)`. The first valid record creates the lead and fixes its `batch_id`. Each later valid record for the same identity increments the duplicate-merge counter and overwrites only fields whose incoming values are non-null. Schema defaults are applied after the available rows have been merged, to fields that remain null.

### 4.2 Event ingestion and ledger

JSONL files are read one line at a time. Every non-empty line contributes to `events_total`. Invalid JSON, non-object JSON values, and records without an `event_id` are counted as malformed and skipped.

Valid events are inserted into `ledger_events`. The `event_id` column is unique, so duplicate event IDs—including duplicates across different drops—are counted and skipped. The ledger also has database triggers that reject `UPDATE` and `DELETE`, enforcing append-only behavior at the database level.

For phone-bearing events, the phone is normalized using the same function as lead ingestion and converted to the same HMAC token. Events that cannot currently be associated with a lead are retained in the ledger and represented in `event_quarantine`. They are not used in reports while unresolved.

A later lead can resolve a previously quarantined event. Event-to-lead associations are recalculated from the current lead set; the event history itself is not modified. `event_quarantine` is a current unresolved-state projection, refreshed from the ledger and leads.

`disposition.override` events do not contain a phone. They are linked in a second pass through `(workflow_id, call_id)`, using the lead association established by other events belonging to the same call.

### 4.3 SQLite tables

| Table | Responsibility |
|---|---|
| `leads` | One canonical lead per workflow and phone token; stores encrypted customer name and non-PII attributes. |
| `ledger_events` | Deduplicated append-only interaction history. |
| `event_quarantine` | Current list of valid events that cannot be linked to a lead. |
| `source_files` | Source path, file kind, SHA-256 digest, and ingestion timestamp for file-level idempotency. |
| `rejections` | Rejected row metadata and reason, without PII. |
| `quality_counters` | Persistent counters used in the data-quality report. |

The database enables foreign-key enforcement. Indexes support lookups by workflow and phone token, and by workflow and call ID. Lead uniqueness is enforced by `(workflow_id, phone_token)` and event uniqueness by `event_id`.

## 5. PII protection

The supplied workflow schemas mark customer name and phone as PII. The implementation avoids storing either in plaintext:

- **Phone:** after normalization, the phone is transformed using HMAC-SHA256 with a secret matching key. The token is deterministic, allowing equality matching between leads and events without persisting the phone number. The final four digits are stored separately because the lead report requires a masked phone number.
- **Customer name:** encrypted with AES-GCM using a random 12-byte nonce. The stored value contains the nonce and the AES-GCM ciphertext/authentication tag.
- **Key separation:** separate key material is derived for phone matching and name encryption using distinct HMAC context strings. A key is required through `--key` or `LEDGER_ENCRYPTION_KEY`; there is no committed default secret.

The current report contract does not require displaying customer names, so the reporting path does not decrypt them. Key management, rotation, and access control would need additional operational support in a production deployment.

## 6. Idempotency and processing order

Each input file is checkpointed using its resolved absolute path and a streamed SHA-256 digest. If that path and digest have already been processed, the file is skipped. If a previously processed path now has different content, ingestion fails rather than silently replaying a modified historical file.

This checkpoint protects lead counters, rejection records, duplicate-merge counters, event counters, and event inserts from changing on a same-file retry. Database uniqueness constraints provide an additional record-level safeguard.

Files within a drop are processed in sorted path order; rows are processed in file order. Drops are processed in the order supplied to the CLI. This preserves the specified first-valid-row and last-non-null merge semantics.

Ingestion is incremental at the source-file level: previously checkpointed files are skipped and newly delivered files are processed. Report generation is not an incremental materialized aggregation; it reconstructs the current associations and report metrics from the persisted leads and event ledger each time.

## 7. Call derivation and reporting rules

A call is created only when a linked `call.initiated` event with a call ID and parseable timestamp exists. Events are associated with a call using workflow, call ID, and lead ID. A call is connected if it has a `call.connected` event. A call is considered telephony-failed if it has a `call.telephony_failed` event.

Effective disposition is selected from recognized disposition events for that workflow: the latest `disposition.override` takes precedence if any override exists; otherwise the latest `disposition.set` is used. Timestamp and event ID are used as a deterministic ordering key. Unknown disposition codes are excluded from effective disposition selection and included in the quality count when linked to a lead.

The disposition catalogue supplies `is_terminal` and `is_success`, keeping workflow outcome metadata separate from report logic.

Lead buckets are evaluated in the assignment's priority order:

1. `yet_to_reach_out` when there are no counted calls.
2. `completed` when any call has a terminal effective disposition.
3. `in_progress_telephony_failed` when every counted call has a telephony-failure event.
4. `in_progress_dialed` otherwise.

Event timestamps are normalized to UTC for storage. Naive timestamps are interpreted as IST as required by the specification. Timestamps are converted to IST for daily grouping and report output.

The five output files are:

- `batch_summary.csv`: lead counts by workflow and the first batch associated with each lead, split by bucket.
- `daily_overview.csv`: calls and connected calls by workflow and IST date, connectivity rate formatted to four decimal places, and distinct successful leads for that date.
- `lead_report.csv`: one row per lead with its schema-defined external reference, masked phone, bucket, call counts, latest initiated call time, current effective disposition, and ever-success flag.
- `rejections.csv`: rejected row metadata and reason, with no PII.
- `data_quality.json`: lead, rejection, warning, event, duplicate, orphan, and unknown-disposition counters.

## 8. Assumptions and edge-case decisions

| Situation | Decision |
|---|---|
| Unknown CSV columns | Ignore them, as they are not part of the workflow schema. |
| Multiple CSV headers map to the same canonical field | Use the first recognized header mapping for that field. |
| Blank CSV rows | Skip them and do not count them. |
| Invalid optional values | Store `NULL` and count a warning only if the row is otherwise accepted. |
| Duplicate lead with a null incoming field | Preserve the previously stored non-null value. |
| Duplicate lead arriving in a later batch | Merge it into the original lead; retain the first valid batch ID. |
| Event has an invalid or absent phone | It cannot be phone-linked and remains unresolved unless it is an override linkable by call ID. |
| Event timestamp cannot be parsed | Store the event with a null normalized timestamp; an initiated event without a parseable timestamp does not create a counted call. |
| Unknown event types | Retain them in the ledger, but they do not contribute to the defined call metrics. |
| Disposition code not in the workflow catalogue | Do not use it as an effective disposition; count it as unknown when the event is linked. |
| Ingested file at an existing path changes | Fail rather than reprocess the changed content as the same source delivery. |
| Naive event timestamp | Interpret as IST, then normalize to UTC for storage. |

## 9. Tests and validation

The automated tests cover:

- Indian phone normalization and invalid phone rejection.
- Supported date formats and impossible dates.
- Header aliases, optional-field warnings, row rejection, blank rows, defaults, and cross-batch merging.
- File-level idempotency across repeated ingestion and cross-drop duplicate event handling.
- Reconciliation and explicit quarantine removal when an event's lead arrives in a later drop.
- Unknown disposition handling, multiple override selection, IST reporting boundaries, and distinct success-lead counts.
- AES-GCM ciphertext randomness/tamper detection and absence of plaintext phone/name values in a SQLite dump.

The small synthetic dataset was also used for an end-to-end smoke test: generate the two drops, ingest `drop_1` followed by `drop_2`, and generate all five reports. The large-scale performance target has not been benchmarked, and the implementation should not be considered verified against the evaluator's fresh seed until that run is completed.

Run the automated tests with:

```bash
pytest solution/test_ledger.py -q
```

## 10. Trade-offs and what I would improve next

1. **Large-scale reporting:** `_events_with_lead()` currently materializes events in Python and report aggregation is performed in application code. For larger volumes, I would move more joins and aggregation into SQL, use bulk inserts, and benchmark memory and runtime using the large generator dataset.
2. **Concurrency:** SQLite is appropriate for the local assignment. For multiple ingestion workers or concurrent application services, I would use PostgreSQL and define transaction and locking boundaries around source-file processing.
3. **Source identity:** the checkpoint uses absolute path plus content hash. If identical files delivered under different paths must be treated as the same source, I would introduce an explicit source-delivery ID or a content-based deduplication policy with documented semantics.
4. **Key management:** production deployment should obtain secrets from a secrets manager/KMS, restrict access, support rotation, and document recovery procedures. Rotation would need to account for both encrypted names and deterministic phone tokens.
5. **Operational recovery:** I would add structured logs, per-file processing status, metrics/alerts for rejection and orphan spikes, retry policies, and an explicit backfill workflow.
6. **Test coverage:** I would add complete expected-output fixtures, malformed-input fuzzing, property tests for normalisers, and large-scale performance tests.

For a production workload around 100k leads/day, I would schedule ingestion on file arrival or a durable batch scheduler, checkpoint each source delivery, process files transactionally, retain rejected records for correction, and make late-event reconciliation repeatable. I would use PostgreSQL with suitable indexes and partitioning if volume justified it, push large aggregations into SQL, monitor pipeline lag and quality counters, and keep raw event history immutable so reports can be rebuilt during backfills.

## 11. Known limitations

- Large-scale performance under the assignment's two-minute target has not been measured.
- Report aggregation is performed in Python rather than entirely in SQL.
- The event-to-lead relationship is derived during processing/reporting rather than stored as a permanent foreign key on each event; this supports late-arriving leads without changing the append-only ledger, but requires re-resolution.
- The current CLI does not expose a customer-name decryption operation; the assignment's reports do not require names to be displayed.
- Key rotation and production secrets management are outside the current implementation.
