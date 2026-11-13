# AI Usage Disclosure

## Tools used

OpenAI Codex.

## What I used them for

Repository inspection; implementation and review of the SQLite ingestion/reporting pipeline;
AES-GCM PII protection; explicit orphan-event quarantine; automated tests; and documentation.

## What I wrote or decided myself

I reviewed the assignment requirements and final implementation, including the choices to use
SQLite, source-file checkpoints, report-time orphan reconciliation, an explicit quarantine view,
AES-GCM encrypted names, HMAC phone tokens, and schema-driven validation/reporting rules.

## Where the AI was wrong or unhelpful

Early drafts needed corrections. Event-ID deduplication alone would still count lead
rejections/row totals twice, so source-file checkpoints were added. A custom local encryption
draft was rejected and replaced with AES-GCM plus a required externally supplied key. The first
test suite was too narrow, so integration tests were added for reruns, late leads, cross-drop
duplicates, multiple overrides, IST boundaries, and PII inspection.

## How I verified AI-generated code

I read the code, ran `python -m pytest -q solution/test_ledger.py` (12 passing tests), generated
the supplied seed-42 small dataset, ingested both drops, generated all five reports, inspected the
quality output, scanned a SQLite dump for sample plaintext PII, and reran ingestion to confirm
reports remained unchanged. The clean-clone command is `pip install -r requirements.txt` followed
by `pytest solution/test_ledger.py -q`.
