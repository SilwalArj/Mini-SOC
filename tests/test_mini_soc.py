import sys
import sqlite3
import tempfile
import unittest
from datetime import datetime, timedelta

from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import database
from models import Event
from parser import parse_log_line
from detector import detect_brute_force
from alerts import create_alert


class TestMiniSOC(unittest.TestCase):

    def test_parse_valid_log(self):
        line = (
            "2026-10-07 15:30:01 INFO "
            "LOGIN_SUCCESS user=arj ip=192.168.1.10"
        )

        event = parse_log_line(line)

        self.assertEqual(event.event_type, "LOGIN_SUCCESS")
        self.assertEqual(event.username, "arj")
        self.assertEqual(event.source_ip, "192.168.1.10")

    def test_reject_malformed_log(self):
        with self.assertRaises(ValueError):
            parse_log_line("this is a broken log entry")

    def test_detect_brute_force(self):
        events = []

        for second in [0, 10, 20, 30, 40]:
            events.append(Event(
                timestamp=f"2026-10-07 15:30:{second:02d}",
                event_type="LOGIN_FAILED",
                username="admin",
                source_ip="192.168.1.42",
                severity="WARN",
                raw_log=f"failed login {second}",
            ))

        alerts = detect_brute_force(events)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["alert_type"], "BRUTE_FORCE")
        self.assertEqual(alerts[0]["severity"], "HIGH")
        self.assertEqual(alerts[0]["source_ip"], "192.168.1.42")
        self.assertEqual(alerts[0]["attempts"], 5)

    def test_no_alert_below_threshold(self):
        events = []

        for second in [0, 10, 20, 30]:
            events.append(Event(
                timestamp=f"2026-10-07 15:30:{second:02d}",
                event_type="LOGIN_FAILED",
                username="admin",
                source_ip="192.168.1.42",
                severity="WARN",
                raw_log=f"failed login {second}",
            ))

        alerts = detect_brute_force(events)

        self.assertEqual(len(alerts), 0)

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = str(Path(self.temp_dir.name) / "test_soc.db")

        self.connection_patch = patch.object(
            database,
            "get_connection",
            side_effect=lambda: sqlite3.connect(self.db_path),
        )
        self.connection_patch.start()

        database.create_tables()

    def tearDown(self):
        self.connection_patch.stop()
        self.temp_dir.cleanup()

    def test_event_persistence_and_deduplication(self):
        event = Event(
            timestamp="2026-10-07 15:30:01",
            event_type="LOGIN_SUCCESS",
            username="arj",
            source_ip="192.168.1.10",
            severity="INFO",
            raw_log="sample event",
        )

        self.assertTrue(database.insert_event(event))
        self.assertFalse(database.insert_event(event))

        stored_events = database.get_events()
        self.assertEqual(len(stored_events), 1)
        self.assertEqual(stored_events[0].username, "arj")

    def test_alert_persistence_and_deduplication(self):
        alert = create_alert(
            alert_type="BRUTE_FORCE",
            severity="HIGH",
            source_ip="192.168.1.42",
            username="admin",
            description="Possible brute-force attack",
            attempts=5,
        )

        self.assertTrue(database.insert_alert(alert))
        self.assertFalse(database.insert_alert(alert))

        stored_alerts = database.get_alerts()
        self.assertEqual(len(stored_alerts), 1)
        self.assertEqual(stored_alerts[0][2], "BRUTE_FORCE")

    def test_alert_status_update(self):
        alert = create_alert(
            alert_type="BRUTE_FORCE",
            severity="HIGH",
            source_ip="192.168.1.42",
            username="admin",
            description="Possible brute-force attack",
            attempts=5,
        )

        database.insert_alert(alert)

        updated = database.update_alert_status(
            1, "INVESTIGATING"
        )

        self.assertTrue(updated)
        self.assertEqual(
            database.get_alerts()[0][6],
            "INVESTIGATING",
        )

    def test_invalid_alert_status(self):
        with self.assertRaises(ValueError):
            database.update_alert_status(1, "INVALID")

    
    def make_failed_events(self, seconds, source_ip="192.168.1.42"):
        events = []

        for index, second in enumerate(seconds):
            timestamp = (
                datetime(2026, 10, 7, 15, 30, 0)
                + timedelta(seconds=second)
            ).strftime("%Y-%m-%d %H:%M:%S")

            events.append(Event(
                timestamp=timestamp,
                event_type="LOGIN_FAILED",
                username="admin",
                source_ip=source_ip,
                severity="WARN",
                raw_log=f"failed login {index}",
            ))

        return events

    def test_no_alert_when_failures_exceed_window(self):
        events = self.make_failed_events([0, 20, 40, 80, 100])

        self.assertEqual(detect_brute_force(events), [])

    def test_alert_when_fifth_failure_is_exactly_60_seconds_later(self):
        events = self.make_failed_events([0, 15, 30, 45, 60])

        alerts = detect_brute_force(events)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["attempts"], 5)

    def test_detection_is_independent_of_input_order(self):
        seconds = [0, 10, 20, 30, 40]
        events = self.make_failed_events(seconds)

        shuffled_events = list(reversed(events))

        original_alerts = detect_brute_force(events)
        reversed_alerts = detect_brute_force(shuffled_events)

        self.assertEqual(len(original_alerts), 1)
        self.assertEqual(len(reversed_alerts), 1)

        self.assertEqual(
            original_alerts[0]["source_ip"],
            reversed_alerts[0]["source_ip"],
        )
        self.assertEqual(
            original_alerts[0]["attempts"],
            reversed_alerts[0]["attempts"],
        )

    def test_different_ips_are_detected_independently(self):
        events = (
            self.make_failed_events(
                [0, 10, 20, 30, 40],
                source_ip="192.168.1.42",
            )
            + self.make_failed_events(
                [0, 10, 20, 30, 40],
                source_ip="192.168.1.55",
            )
        )

        alerts = detect_brute_force(events)

        self.assertEqual(len(alerts), 2)
        self.assertEqual(
            {alert["source_ip"] for alert in alerts},
            {"192.168.1.42", "192.168.1.55"},
        )



if __name__ == "__main__":
    unittest.main()
