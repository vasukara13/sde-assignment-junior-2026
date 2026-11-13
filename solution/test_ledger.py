from __future__ import annotations

import csv
import json
from pathlib import Path

from cryptography.exceptions import InvalidTag
import pytest

from ledger import Ledger, normalise_phone, parse_date


def write_leads(drop: Path, rows: list[list[str]], batch: str = "batch_001") -> None:
    path = drop / "leads" / "motor_renewal" / f"{batch}.csv"
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(["Insured Name", "Mobile No", "Policy No", "Expiry Date", "Premium", "Language"])
        writer.writerows(rows)


def write_events(drop: Path, events: list[dict]) -> None:
    path = drop / "events" / "events_0001.jsonl"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(json.dumps(event) for event in events) + "\n", encoding="utf-8")


def event(event_id: str, event_type: str, phone: str | None = "+917718750036", call_id: str = "call-1", code: str | None = None, at: str = "2026-10-01T18:45:00Z") -> dict:
    value = {"event_id": event_id, "event_type": event_type, "workflow_id": "motor_renewal", "call_id": call_id, "occurred_at": at, "payload": {}}
    if phone is not None:
        value["phone"] = phone
    if code is not None:
        value["payload"]["disposition_code"] = code
    return value


def test_phone_normalisation() -> None:
    assert normalise_phone("(+91) 77187 50036") == "+917718750036"
    assert normalise_phone("07718750036") == "+917718750036"
    assert normalise_phone("5" + "1" * 9) is None


def test_dates_are_day_first_and_strict() -> None:
    assert parse_date("03/10/2026") == "2026-10-03"
    assert parse_date("01-Dec-2026") == "2026-12-01"
    assert parse_date("31/02/2026") is None


def test_override_is_effective_and_bucket_is_completed(tmp_path) -> None:
    db = tmp_path / "ledger.sqlite3"
    ledger = Ledger(db, "test-key")
    try:
        schema = ledger.schemas["motor_renewal"]
        ledger._merge(schema, "batch_001", {
            "customer_name": "Ada", "phone": "+917718750036", "policy_number": "P-1",
            "policy_expiry": None, "premium_amount": None, "preferred_language": None,
        })
        token = ledger.protector.token("+917718750036")
        rows = [
            ("i", "call.initiated", "2026-10-01T04:30:00+00:00", token, None),
            ("s", "disposition.set", "2026-10-01T04:31:00+00:00", token, "callback_requested"),
            ("o", "disposition.override", "2026-10-01T04:32:00+00:00", None, "renewed"),
        ]
        for event_id, typ, at, phone, code in rows:
            ledger.db.execute(
                "INSERT INTO ledger_events(event_id,event_type,workflow_id,call_id,occurred_at_utc,phone_token,disposition_code,payload_json) VALUES (?,?,?,?,?,?,?,?)",
                (event_id, typ, "motor_renewal", "call-1", at, phone, code, "{}"),
            )
        ledger.db.commit()
        out = tmp_path / "reports"
        ledger.report(out)
        row = next(csv.DictReader((out / "lead_report.csv").open()))
        assert row["current_disposition"] == "renewed"
        assert row["bucket"] == "completed"
        assert row["ever_success"] == "true"
    finally:
        ledger.close()


def test_bucket_priority() -> None:
    catalogue = {("w", "done"): (True, False)}
    assert Ledger._bucket([], "w", catalogue) == "yet_to_reach_out"
    assert Ledger._bucket([{"effective": None, "failed": True}], "w", catalogue) == "in_progress_telephony_failed"
    assert Ledger._bucket([{"effective": "done", "failed": False}], "w", catalogue) == "completed"


def test_lead_aliases_warnings_merge_and_defaults(tmp_path) -> None:
    ledger = Ledger(tmp_path / "db.sqlite", "test-key")
    try:
        drop = tmp_path / "drop"
        write_leads(drop, [
            ["Ada", "+91 77187 50036", "P-1", "not-a-date", "not-money", "English"],
            ["   ", "", "", "", "", ""],
            ["", "9932302346", "P-2", "", "", ""],
        ])
        ledger.ingest(drop)
        counters = {r["counter"]: r["value"] for r in ledger.db.execute("SELECT counter,value FROM quality_counters")}
        assert counters["lead_rows_total"] == 2
        assert counters["field_warnings"] == 3
        assert counters["rejection:missing_required:customer_name"] == 1
        row = ledger.db.execute("SELECT attributes_json FROM leads").fetchone()
        attrs = json.loads(row["attributes_json"])
        assert attrs["policy_expiry"] is None and attrs["premium_amount"] is None and attrs["preferred_language"] is None
        ledger.report(tmp_path / "reports")
        attrs = json.loads(ledger.db.execute("SELECT attributes_json FROM leads").fetchone()["attributes_json"])
        assert attrs["preferred_language"] == "en"
    finally:
        ledger.close()


def test_file_idempotency_preserves_reports_and_counters(tmp_path) -> None:
    ledger = Ledger(tmp_path / "db.sqlite", "test-key")
    try:
        drop = tmp_path / "drop"
        write_leads(drop, [["Ada", "+917718750036", "P-1", "", "", ""]])
        write_events(drop, [event("i", "call.initiated"), event("c", "call.connected")])
        out = tmp_path / "reports"
        ledger.ingest(drop); ledger.report(out)
        first_reports = {path.name: path.read_bytes() for path in out.iterdir()}
        first_counters = list(ledger.db.execute("SELECT counter,value FROM quality_counters ORDER BY counter"))
        ledger.ingest(drop); ledger.report(out)
        assert first_reports == {path.name: path.read_bytes() for path in out.iterdir()}
        assert first_counters == list(ledger.db.execute("SELECT counter,value FROM quality_counters ORDER BY counter"))
    finally:
        ledger.close()


def test_late_lead_moves_event_out_of_explicit_quarantine(tmp_path) -> None:
    ledger = Ledger(tmp_path / "db.sqlite", "test-key")
    try:
        first, second, out = tmp_path / "drop_1", tmp_path / "drop_2", tmp_path / "reports"
        write_events(first, [event("i", "call.initiated")])
        ledger.ingest(first); ledger.report(out)
        assert json.loads((out / "data_quality.json").read_text())["orphan_events"] == 1
        assert ledger.db.execute("SELECT COUNT(*) FROM event_quarantine").fetchone()[0] == 1
        write_leads(second, [["Ada", "+917718750036", "P-1", "", "", ""]])
        ledger.ingest(second); ledger.report(out)
        assert json.loads((out / "data_quality.json").read_text())["orphan_events"] == 0
        assert ledger.db.execute("SELECT COUNT(*) FROM event_quarantine").fetchone()[0] == 0
        assert next(csv.DictReader((out / "lead_report.csv").open()))["total_calls"] == "1"
    finally:
        ledger.close()


def test_unknown_disposition_is_counted_ignored_and_pii_is_not_plaintext(tmp_path) -> None:
    ledger = Ledger(tmp_path / "db.sqlite", "test-key")
    try:
        drop, out = tmp_path / "drop", tmp_path / "reports"
        write_leads(drop, [["Ada Lovelace", "+917718750036", "P-1", "", "", ""]])
        write_events(drop, [event("i", "call.initiated"), event("d", "disposition.set", code="NOT_A_REAL_CODE")])
        ledger.ingest(drop); ledger.report(out)
        assert json.loads((out / "data_quality.json").read_text())["unknown_disposition_events"] == 1
        row = next(csv.DictReader((out / "lead_report.csv").open()))
        assert row["current_disposition"] == "" and row["ever_success"] == "false"
        database_dump = "\n".join(ledger.db.iterdump())
        assert "Ada Lovelace" not in database_dump and "+917718750036" not in database_dump
    finally:
        ledger.close()


def test_cross_batch_merge_preserves_batch_and_last_non_null_value(tmp_path) -> None:
    ledger = Ledger(tmp_path / "db.sqlite", "test-key")
    try:
        first, second = tmp_path / "drop_1", tmp_path / "drop_2"
        write_leads(first, [["Ada", "+917718750036", "P-1", "", "1000", ""]], "batch_001")
        write_leads(second, [["Ada Updated", "07718750036", "P-2", "", "2500", "hi"]], "batch_003")
        ledger.ingest(first); ledger.ingest(second); ledger.report(tmp_path / "reports")
        lead = ledger.db.execute("SELECT batch_id,attributes_json FROM leads").fetchone()
        attrs = json.loads(lead["attributes_json"])
        assert lead["batch_id"] == "batch_001"
        assert attrs["policy_number"] == "P-2"
        assert attrs["premium_amount"] == "2500.00"
        assert attrs["preferred_language"] == "hi"
        assert ledger.db.execute("SELECT value FROM quality_counters WHERE counter='duplicate_lead_rows_merged'").fetchone()[0] == 1
    finally:
        ledger.close()


def test_malformed_and_cross_drop_duplicate_events_are_counted(tmp_path) -> None:
    ledger = Ledger(tmp_path / "db.sqlite", "test-key")
    try:
        first, second, out = tmp_path / "drop_1", tmp_path / "drop_2", tmp_path / "reports"
        write_leads(first, [["Ada", "+917718750036", "P-1", "", "", ""]])
        write_events(first, [event("same", "call.initiated")])
        duplicate_file = second / "events" / "events_1001.jsonl"
        duplicate_file.parent.mkdir(parents=True, exist_ok=True)
        duplicate_file.write_text(json.dumps(event("same", "call.initiated")) + "\nnot-json\n{}\n", encoding="utf-8")
        ledger.ingest(first); ledger.ingest(second); ledger.report(out)
        quality = json.loads((out / "data_quality.json").read_text())
        assert quality["events_total"] == 4
        assert quality["duplicate_events_dropped"] == 1
        assert quality["malformed_events"] == 2
        assert next(csv.DictReader((out / "lead_report.csv").open()))["total_calls"] == "1"
    finally:
        ledger.close()


def test_latest_override_and_ist_daily_success_lead_deduplication(tmp_path) -> None:
    ledger = Ledger(tmp_path / "db.sqlite", "test-key")
    try:
        drop, out = tmp_path / "drop", tmp_path / "reports"
        write_leads(drop, [["Ada", "+917718750036", "P-1", "", "", ""]])
        # 20:00 UTC is 01:30 on 2 October in IST. Two successful calls count one success lead.
        write_events(drop, [
            event("i1", "call.initiated", call_id="call-1", at="2026-10-01T20:00:00Z"),
            event("s1", "disposition.set", call_id="call-1", code="renewed", at="2026-10-01T20:02:00Z"),
            event("o1", "disposition.override", phone=None, call_id="call-1", code="not_interested", at="2026-10-01T20:03:00Z"),
            event("o2", "disposition.override", phone=None, call_id="call-1", code="renewed", at="2026-10-01T20:04:00Z"),
            event("i2", "call.initiated", call_id="call-2", at="2026-10-01T20:10:00Z"),
            event("s2", "disposition.set", call_id="call-2", code="renewed", at="2026-10-01T20:12:00Z"),
        ])
        ledger.ingest(drop); ledger.report(out)
        daily = next(csv.DictReader((out / "daily_overview.csv").open()))
        lead = next(csv.DictReader((out / "lead_report.csv").open()))
        assert daily["date"] == "2026-10-02"
        assert daily["total_calls"] == "2" and daily["success_leads"] == "1"
        assert lead["current_disposition"] == "renewed"
        assert lead["last_call_at"] == "2026-10-02T01:40:00+05:30"
    finally:
        ledger.close()


def test_aes_gcm_ciphertext_is_random_and_authenticated(tmp_path) -> None:
    ledger = Ledger(tmp_path / "db.sqlite", "test-key")
    try:
        first = ledger.protector.encrypt("Ada Lovelace")
        second = ledger.protector.encrypt("Ada Lovelace")
        assert first != second
        raw = bytes.fromhex(first)
        assert ledger.protector.aes.decrypt(raw[:12], raw[12:], None) == b"Ada Lovelace"
        tampered = raw[:-1] + bytes([raw[-1] ^ 1])
        with pytest.raises(InvalidTag):
            ledger.protector.aes.decrypt(tampered[:12], tampered[12:], None)
    finally:
        ledger.close()
