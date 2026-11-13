"""SQLite interaction-ledger ingestion and reporting for Assignment A."""
from __future__ import annotations

import csv
import hashlib
import hmac
import json
import os
import re
import sqlite3
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
from pathlib import Path
from typing import Any, Iterable

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

IST = timezone(timedelta(hours=5, minutes=30))
HEADER_SPACE = re.compile(r"[_\s]+")
PHONE_DIGITS = re.compile(r"\D+")
MONEY_PREFIX = re.compile(r"^(?:₹|rs\.?|inr)\s*", re.IGNORECASE)


def normalise_header(value: str) -> str:
    return HEADER_SPACE.sub(" ", value.strip().lower())


def normalise_phone(value: str) -> str | None:
    digits = PHONE_DIGITS.sub("", value)
    if len(digits) == 12 and digits.startswith("91"):
        digits = digits[2:]
    elif len(digits) == 11 and digits.startswith("0"):
        digits = digits[1:]
    return "+91" + digits if len(digits) == 10 and digits[0] in "6789" else None


def parse_date(value: str) -> str | None:
    for fmt in ("%Y-%m-%d", "%d/%m/%Y", "%d-%m-%Y", "%d-%b-%Y"):
        try:
            return datetime.strptime(value, fmt).date().isoformat()
        except ValueError:
            pass
    return None


def parse_decimal(value: str) -> str | None:
    try:
        result = Decimal(MONEY_PREFIX.sub("", value.strip()).replace(",", ""))
    except InvalidOperation:
        return None
    if not result.is_finite() or result < 0:
        return None
    return str(result.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP))


def parse_timestamp(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00") if value.endswith("Z") else datetime.fromisoformat(value)
        return (parsed.replace(tzinfo=IST) if parsed.tzinfo is None else parsed).astimezone(timezone.utc)
    except ValueError:
        return None


class Protector:
    """Tokenise phones and encrypt names with independently derived AES-GCM key material."""
    def __init__(self, secret: str | None = None) -> None:
        value = secret or os.environ.get("LEDGER_ENCRYPTION_KEY")
        if not value:
            raise ValueError("LEDGER_ENCRYPTION_KEY (or --key) is required; do not use a committed default key")
        master = value.encode("utf-8")
        self.matching_key = hmac.new(master, b"assignment-a:phone-token:v1", hashlib.sha256).digest()
        self.encryption_key = hmac.new(master, b"assignment-a:customer-name:aes-gcm:v1", hashlib.sha256).digest()
        self.aes = AESGCM(self.encryption_key)

    def token(self, value: str) -> str:
        return hmac.new(self.matching_key, value.encode("utf-8"), hashlib.sha256).hexdigest()

    def encrypt(self, value: str) -> str:
        nonce = os.urandom(12)
        # AES-GCM ciphertext includes its 16-byte authentication tag.
        return (nonce + self.aes.encrypt(nonce, value.encode("utf-8"), None)).hex()


class Ledger:
    def __init__(self, db_path: str | Path, secret: str | None = None) -> None:
        self.path = Path(db_path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(self.path)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA foreign_keys = ON")
        self.protector = Protector(secret)
        self.root = Path(__file__).resolve().parents[1]
        self.schemas = self._load_schemas()
        self._create_schema()

    def close(self) -> None:
        self.db.close()

    def _load_schemas(self) -> dict[str, dict[str, Any]]:
        return {(data := json.loads(p.read_text(encoding="utf-8")))["workflow_id"]: data for p in (self.root / "assignment-a-data/schemas").glob("*.json")}

    def _create_schema(self) -> None:
        self.db.executescript("""
        CREATE TABLE IF NOT EXISTS source_files (source_path TEXT PRIMARY KEY, kind TEXT NOT NULL, sha256 TEXT NOT NULL, ingested_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
        CREATE TABLE IF NOT EXISTS leads (id INTEGER PRIMARY KEY, workflow_id TEXT NOT NULL, phone_token TEXT NOT NULL, phone_last4 TEXT NOT NULL, customer_name_encrypted TEXT, batch_id TEXT NOT NULL, attributes_json TEXT NOT NULL, UNIQUE(workflow_id,phone_token));
        CREATE INDEX IF NOT EXISTS ix_lead_phone ON leads(workflow_id,phone_token);
        CREATE TABLE IF NOT EXISTS rejections (id INTEGER PRIMARY KEY, workflow_id TEXT NOT NULL, batch_id TEXT NOT NULL, row_number INTEGER NOT NULL, reason TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS quality_counters (counter TEXT PRIMARY KEY, value INTEGER NOT NULL DEFAULT 0);
        CREATE TABLE IF NOT EXISTS ledger_events (id INTEGER PRIMARY KEY, event_id TEXT NOT NULL UNIQUE, event_type TEXT, workflow_id TEXT, call_id TEXT, occurred_at_utc TEXT, phone_token TEXT, disposition_code TEXT, payload_json TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS event_quarantine (event_id TEXT PRIMARY KEY REFERENCES ledger_events(event_id) ON DELETE RESTRICT, reason TEXT NOT NULL, quarantined_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
        CREATE INDEX IF NOT EXISTS ix_event_phone ON ledger_events(workflow_id,phone_token);
        CREATE INDEX IF NOT EXISTS ix_event_call ON ledger_events(workflow_id,call_id);
        CREATE TRIGGER IF NOT EXISTS prevent_ledger_event_update BEFORE UPDATE ON ledger_events BEGIN SELECT RAISE(ABORT, 'ledger_events is append-only'); END;
        CREATE TRIGGER IF NOT EXISTS prevent_ledger_event_delete BEFORE DELETE ON ledger_events BEGIN SELECT RAISE(ABORT, 'ledger_events is append-only'); END;
        """)
        self.db.commit()

    def _count(self, name: str, amount: int = 1) -> None:
        self.db.execute("INSERT INTO quality_counters(counter,value) VALUES (?,?) ON CONFLICT(counter) DO UPDATE SET value=value+excluded.value", (name, amount))

    def _checkpoint(self, path: Path, kind: str) -> bool:
        key, digest = str(path.resolve()), self._file_digest(path)
        old = self.db.execute("SELECT sha256 FROM source_files WHERE source_path=?", (key,)).fetchone()
        if old:
            if old["sha256"] != digest:
                raise ValueError(f"refusing changed source file already ingested: {path}")
            return True
        self.db.execute("INSERT INTO source_files(source_path,kind,sha256) VALUES (?,?,?)", (key, kind, digest))
        return False

    @staticmethod
    def _file_digest(path: Path) -> str:
        """Hash large source files incrementally instead of loading them all into memory."""
        digest = hashlib.sha256()
        with path.open("rb") as fh:
            for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()

    def ingest(self, drop: str | Path) -> None:
        base = Path(drop)
        if not base.is_dir():
            raise ValueError(f"drop directory does not exist: {base}")
        for path in sorted(base.rglob("leads/*/*.csv"), key=str):
            self._ingest_leads(path)
        for path in sorted(base.rglob("events/*.jsonl"), key=str):
            self._ingest_events(path)
        self._refresh_quarantine()
        self.db.commit()

    def _ingest_leads(self, path: Path) -> None:
        try:
            workflow = path.parts[path.parts.index("leads") + 1]
        except (ValueError, IndexError):
            return
        schema = self.schemas.get(workflow)
        if not schema or self._checkpoint(path, "leads"):
            return
        aliases = {normalise_header(alias): f["name"] for f in schema["fields"] for alias in [f["name"], *f.get("aliases", [])]}
        with path.open(encoding="utf-8-sig", newline="") as fh:
            reader = csv.reader(fh)
            try:
                header = next(reader)
            except StopIteration:
                return
            mapped, seen = {}, set()
            for index, cell in enumerate(header):
                field = aliases.get(normalise_header(cell))
                if field and field not in seen:
                    mapped[index], seen = field, seen | {field}
            row_number = 0
            for row in reader:
                if not any(cell.strip() for cell in row):
                    continue
                row_number += 1
                raw = {f["name"]: "" for f in schema["fields"]}
                for index, field in mapped.items():
                    raw[field] = row[index].strip() if index < len(row) else ""
                self._count("lead_rows_total")
                valid, values, reason, warnings = self._validate(schema, raw)
                if not valid:
                    self._count("lead_rows_rejected"); self._count("rejection:" + reason)
                    self.db.execute("INSERT INTO rejections(workflow_id,batch_id,row_number,reason) VALUES (?,?,?,?)", (workflow, path.stem, row_number, reason))
                else:
                    self._count("field_warnings", warnings)
                    self._merge(schema, path.stem, values)

    def _validate(self, schema: dict[str, Any], raw: dict[str, str]) -> tuple[bool, dict[str, str | None], str | None, int]:
        values: dict[str, str | None] = {}; warnings = 0
        for field in schema["fields"]:
            name, typ, value = field["name"], field["type"], raw[field["name"]]
            if not value:
                if field.get("required"):
                    return False, values, "missing_required:" + name, warnings
                values[name] = None; continue
            if typ == "string": parsed = value
            elif typ == "phone": parsed = normalise_phone(value)
            elif typ == "date": parsed = parse_date(value)
            elif typ == "decimal": parsed = parse_decimal(value)
            elif typ == "enum": parsed = value.lower() if value.lower() in {str(v).lower() for v in field.get("values", [])} else None
            else: parsed = None
            if parsed is None:
                if typ == "phone": return False, values, "invalid_phone", warnings
                if field.get("required"): return False, values, "invalid_" + typ, warnings
                warnings += 1
            values[name] = parsed
        return True, values, None, warnings

    def _merge(self, schema: dict[str, Any], batch: str, values: dict[str, str | None]) -> None:
        workflow, phone = schema["workflow_id"], values["phone"]
        assert phone
        token = self.protector.token(phone)
        old = self.db.execute("SELECT * FROM leads WHERE workflow_id=? AND phone_token=?", (workflow, token)).fetchone()
        fields = {f["name"]: f for f in schema["fields"]}
        attrs = {name: values[name] for name, f in fields.items() if not f.get("pii")}
        name = self.protector.encrypt(values["customer_name"]) if values.get("customer_name") else None
        if old is None:
            self.db.execute("INSERT INTO leads(workflow_id,phone_token,phone_last4,customer_name_encrypted,batch_id,attributes_json) VALUES (?,?,?,?,?,?)", (workflow, token, phone[-4:], name, batch, json.dumps(attrs, sort_keys=True)))
            return
        merged = json.loads(old["attributes_json"])
        merged.update({k: v for k, v in attrs.items() if v is not None})
        self._count("duplicate_lead_rows_merged")
        self.db.execute("UPDATE leads SET customer_name_encrypted=COALESCE(?,customer_name_encrypted),attributes_json=? WHERE id=?", (name, json.dumps(merged, sort_keys=True), old["id"]))

    def _ingest_events(self, path: Path) -> None:
        if self._checkpoint(path, "events"):
            return
        with path.open(encoding="utf-8") as fh:
            for line in fh:
                if not line.strip(): continue
                self._count("events_total")
                try: event = json.loads(line)
                except json.JSONDecodeError: self._count("malformed_events"); continue
                if not isinstance(event, dict) or not event.get("event_id"):
                    self._count("malformed_events"); continue
                event_type, payload = event.get("event_type"), event.get("payload") if isinstance(event.get("payload"), dict) else {}
                phone = normalise_phone(event["phone"]) if isinstance(event.get("phone"), str) else None
                at = parse_timestamp(event.get("occurred_at"))
                values = (str(event["event_id"]), str(event_type) if event_type is not None else None, str(event["workflow_id"]) if event.get("workflow_id") is not None else None, str(event["call_id"]) if event.get("call_id") is not None else None, at.isoformat() if at else None, self.protector.token(phone) if phone else None, str(payload.get("disposition_code")) if str(event_type).startswith("disposition.") and payload.get("disposition_code") is not None else None, json.dumps(payload, sort_keys=True, separators=(",", ":")))
                try:
                    self.db.execute("INSERT INTO ledger_events(event_id,event_type,workflow_id,call_id,occurred_at_utc,phone_token,disposition_code,payload_json) VALUES (?,?,?,?,?,?,?,?)", values)
                except sqlite3.IntegrityError: self._count("duplicate_events_dropped")

    def _catalogue(self) -> dict[tuple[str, str], tuple[bool, bool]]:
        with (self.root / "assignment-a-data/schemas/dispositions.csv").open(encoding="utf-8", newline="") as fh:
            return {(r["workflow_id"], r["code"].lower()): (r["is_terminal"] == "true", r["is_success"] == "true") for r in csv.DictReader(fh)}

    def _events_with_lead(self) -> list[dict[str, Any]]:
        events = [dict(r) for r in self.db.execute("SELECT * FROM ledger_events ORDER BY id")]
        lookup = {(r["workflow_id"], r["phone_token"]): r["id"] for r in self.db.execute("SELECT id,workflow_id,phone_token FROM leads")}
        calls: dict[tuple[str, str], int] = {}
        for e in events:
            e["lead_id"] = lookup.get((e["workflow_id"], e["phone_token"])) if e["workflow_id"] and e["phone_token"] else None
            if e["event_type"] != "disposition.override" and e["call_id"] and e["lead_id"] is not None: calls.setdefault((e["workflow_id"], e["call_id"]), e["lead_id"])
        for e in events:
            if e["event_type"] == "disposition.override" and e["workflow_id"] and e["call_id"]: e["lead_id"] = calls.get((e["workflow_id"], e["call_id"]))
        return events

    def _refresh_quarantine(self, events: list[dict[str, Any]] | None = None) -> list[dict[str, Any]]:
        """Maintain explicit current quarantine state without mutating the ledger."""
        events = events if events is not None else self._events_with_lead()
        self.db.execute("DELETE FROM event_quarantine")
        self.db.executemany(
            "INSERT INTO event_quarantine(event_id,reason) VALUES (?,?)",
            [(event["event_id"], "unlinked_lead") for event in events if event["lead_id"] is None],
        )
        return events

    def _apply_defaults(self) -> None:
        """Apply schema defaults only after all source rows have been merged."""
        for row in list(self.db.execute("SELECT id,workflow_id,attributes_json FROM leads")):
            attrs = json.loads(row["attributes_json"])
            changed = False
            for field in self.schemas[row["workflow_id"]]["fields"]:
                if not field.get("pii") and attrs.get(field["name"]) is None and "default" in field:
                    attrs[field["name"]] = field["default"]
                    changed = True
            if changed:
                self.db.execute("UPDATE leads SET attributes_json=? WHERE id=?", (json.dumps(attrs, sort_keys=True), row["id"]))

    @staticmethod
    def _time_key(e: dict[str, Any]) -> tuple[str, str]: return (e["occurred_at_utc"] or "", e["event_id"])

    def report(self, output: str | Path) -> None:
        out = Path(output); out.mkdir(parents=True, exist_ok=True)
        self._apply_defaults()
        events = self._refresh_quarantine()
        self.db.commit()
        leads = [dict(r) for r in self.db.execute("SELECT * FROM leads")]; cat = self._catalogue()
        calls: dict[tuple[str, str, int], dict[str, Any]] = {}
        for e in events:
            if e["event_type"] == "call.initiated" and e["lead_id"] is not None and e["call_id"] and e["occurred_at_utc"]:
                key = (e["workflow_id"], e["call_id"], e["lead_id"])
                if key not in calls or self._time_key(e) < self._time_key(calls[key]["initiated"]): calls[key] = {"workflow_id": e["workflow_id"], "lead_id": e["lead_id"], "call_id": e["call_id"], "initiated": e, "events": []}
        for e in events:
            key = (e["workflow_id"], e["call_id"], e["lead_id"])
            if e["lead_id"] is not None and e["call_id"] and key in calls: calls[key]["events"].append(e)
        by_lead: dict[int, list[dict[str, Any]]] = defaultdict(list)
        for call in calls.values():
            choices = [e for e in call["events"] if e["event_type"] in ("disposition.set", "disposition.override") and (e["workflow_id"], e["disposition_code"]) in cat]
            overrides = [e for e in choices if e["event_type"] == "disposition.override"]
            picked = max(overrides or [e for e in choices if e["event_type"] == "disposition.set"], key=self._time_key) if choices else None
            call["effective"] = picked["disposition_code"] if picked else None; call["connected"] = any(e["event_type"] == "call.connected" for e in call["events"]); call["failed"] = any(e["event_type"] == "call.telephony_failed" for e in call["events"]); call["at"] = datetime.fromisoformat(call["initiated"]["occurred_at_utc"]); by_lead[call["lead_id"]].append(call)
        for group in by_lead.values(): group.sort(key=lambda c: self._time_key(c["initiated"]))
        self._batch(out / "batch_summary.csv", leads, by_lead, cat); self._daily(out / "daily_overview.csv", by_lead, cat); self._lead_report(out / "lead_report.csv", leads, by_lead, cat); self._rejections(out / "rejections.csv"); self._quality(out / "data_quality.json", events, cat)

    @staticmethod
    def _bucket(calls: list[dict[str, Any]], workflow: str, cat: dict[tuple[str, str], tuple[bool, bool]]) -> str:
        if not calls: return "yet_to_reach_out"
        if any(c["effective"] and cat[(workflow, c["effective"])][0] for c in calls): return "completed"
        return "in_progress_telephony_failed" if all(c["failed"] for c in calls) else "in_progress_dialed"

    @staticmethod
    def _write(path: Path, fields: list[str], rows: Iterable[dict[str, Any]]) -> None:
        with path.open("w", encoding="utf-8", newline="") as fh:
            writer = csv.DictWriter(fh, fieldnames=fields, lineterminator="\n"); writer.writeheader(); writer.writerows(rows)

    def _batch(self, path: Path, leads: list[dict[str, Any]], by_lead: dict[int, list[dict[str, Any]]], cat: dict[tuple[str, str], tuple[bool, bool]]) -> None:
        groups: dict[tuple[str, str], Counter[str]] = defaultdict(Counter)
        for lead in leads: groups[(lead["workflow_id"], lead["batch_id"])][self._bucket(by_lead[lead["id"]], lead["workflow_id"], cat)] += 1
        fields = ["workflow_id", "batch_id", "total_leads", "yet_to_reach_out", "in_progress_telephony_failed", "in_progress_dialed", "completed"]
        self._write(path, fields, [{"workflow_id": wf, "batch_id": batch, "total_leads": sum(c.values()), **{x: c[x] for x in fields[3:]}} for (wf, batch), c in sorted(groups.items())])

    def _daily(self, path: Path, by_lead: dict[int, list[dict[str, Any]]], cat: dict[tuple[str, str], tuple[bool, bool]]) -> None:
        groups: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
        for calls in by_lead.values():
            for c in calls: groups[(c["workflow_id"], c["at"].astimezone(IST).date().isoformat())].append(c)
        rows = []
        for (wf, day), calls in sorted(groups.items()):
            total, connected = len(calls), sum(c["connected"] for c in calls); success = {c["lead_id"] for c in calls if c["effective"] and cat[(wf, c["effective"])][1]}
            rows.append({"workflow_id": wf, "date": day, "total_calls": total, "connected_calls": connected, "connectivity_rate": f"{connected / total:.4f}", "success_leads": len(success)})
        self._write(path, ["workflow_id", "date", "total_calls", "connected_calls", "connectivity_rate", "success_leads"], rows)

    def _lead_report(self, path: Path, leads: list[dict[str, Any]], by_lead: dict[int, list[dict[str, Any]]], cat: dict[tuple[str, str], tuple[bool, bool]]) -> None:
        rows = []
        for lead in leads:
            attrs, calls = json.loads(lead["attributes_json"]), by_lead[lead["id"]]; ref = next(f["name"] for f in self.schemas[lead["workflow_id"]]["fields"] if f.get("reference")); last = max(calls, key=lambda c: self._time_key(c["initiated"])) if calls else None; with_disp = [c for c in calls if c["effective"]]; current = max(with_disp, key=lambda c: self._time_key(c["initiated"])) if with_disp else None
            rows.append({"workflow_id": lead["workflow_id"], "external_ref": attrs.get(ref, ""), "batch_id": lead["batch_id"], "phone_masked": "+91******" + lead["phone_last4"], "bucket": self._bucket(calls, lead["workflow_id"], cat), "total_calls": len(calls), "connected_calls": sum(c["connected"] for c in calls), "last_call_at": last["at"].astimezone(IST).isoformat(timespec="seconds") if last else "", "current_disposition": current["effective"] if current else "", "ever_success": "true" if any(c["effective"] and cat[(lead["workflow_id"], c["effective"])][1] for c in calls) else "false"})
        rows.sort(key=lambda r: (r["workflow_id"], r["external_ref"])); self._write(path, ["workflow_id", "external_ref", "batch_id", "phone_masked", "bucket", "total_calls", "connected_calls", "last_call_at", "current_disposition", "ever_success"], rows)

    def _rejections(self, path: Path) -> None:
        self._write(path, ["workflow_id", "batch_id", "row_number", "reason"], [dict(r) for r in self.db.execute("SELECT workflow_id,batch_id,row_number,reason FROM rejections ORDER BY workflow_id,batch_id,row_number")])

    def _quality(self, path: Path, events: list[dict[str, Any]], cat: dict[tuple[str, str], tuple[bool, bool]]) -> None:
        counters = {r["counter"]: r["value"] for r in self.db.execute("SELECT counter,value FROM quality_counters")}; reasons = {k[10:]: v for k, v in counters.items() if k.startswith("rejection:")}
        result = {"lead_rows_total": counters.get("lead_rows_total", 0), "lead_rows_rejected": counters.get("lead_rows_rejected", 0), "rejections_by_reason": dict(sorted(reasons.items())), "duplicate_lead_rows_merged": counters.get("duplicate_lead_rows_merged", 0), "field_warnings": counters.get("field_warnings", 0), "events_total": counters.get("events_total", 0), "malformed_events": counters.get("malformed_events", 0), "duplicate_events_dropped": counters.get("duplicate_events_dropped", 0), "orphan_events": sum(e["lead_id"] is None for e in events), "unknown_disposition_events": sum(e["lead_id"] is not None and str(e["event_type"]).startswith("disposition.") and (e["workflow_id"], e["disposition_code"]) not in cat for e in events)}
        path.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
