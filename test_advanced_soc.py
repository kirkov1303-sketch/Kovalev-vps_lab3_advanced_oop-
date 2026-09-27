import unittest
from advanced_soc import SecurityEvent, IPUtils, BlacklistManager, audit_logger

class TestSecurityEvent(unittest.TestCase):
    def test_init_and_properties(self):
        event = SecurityEvent("2026-09-13 10:00:00", "192.168.1.10", "SSH_LOGIN", severity=2)
        self.assertEqual(event.timestamp, "2026-09-13 10:00:00")
        self.assertEqual(event.source_ip, "192.168.1.10")
        self.assertEqual(event.event_type, "SSH_LOGIN")
        self.assertEqual(event.severity, 2)
        self.assertFalse(event.is_critical)

    def test_severity_validation(self):
        event = SecurityEvent("2026-09-13 10:00:00", "192.168.1.10", "SSH_LOGIN", severity=5)
        self.assertTrue(event.is_critical)

        with self.assertRaises(ValueError):
            event.severity = 6

        with self.assertRaises(ValueError):
            event.severity = 0

    def test_from_syslog(self):
        raw = "2026-09-13 12:00:00 [SSH] Failed login from 192.168.1.50"
        event = SecurityEvent.from_syslog(raw)
        self.assertEqual(event.timestamp, "2026-09-13 12:00:00")
        self.assertEqual(event.event_type, "SSH")
        self.assertEqual(event.source_ip, "192.168.1.50")
        self.assertEqual(event.severity, 3)

    def test_from_syslog_critical(self):
        raw = "2026-09-13 12:05:00 [WEB] Detected SQLi attack payload from 10.0.0.99"
        event = SecurityEvent.from_syslog(raw)
        self.assertEqual(event.source_ip, "10.0.0.99")
        self.assertEqual(event.severity, 5)
        self.assertTrue(event.is_critical)

    def test_from_dict(self):
        data = {
            "timestamp": "2026-09-13 13:00:00",
            "source_ip": "10.0.0.1",
            "event_type": "FIREWALL",
            "severity": 4
        }
        event = SecurityEvent.from_dict(data)
        self.assertEqual(event.source_ip, "10.0.0.1")
        self.assertTrue(event.is_critical)


class TestIPUtils(unittest.TestCase):
    def test_is_private(self):
        self.assertTrue(IPUtils.is_private("192.168.1.1"))
        self.assertTrue(IPUtils.is_private("10.0.0.5"))
        self.assertTrue(IPUtils.is_private("172.16.0.1"))
        self.assertTrue(IPUtils.is_private("127.0.0.1"))
        self.assertFalse(IPUtils.is_private("8.8.8.8"))
        self.assertFalse(IPUtils.is_private("1.1.1.1"))

    def test_mask_ip(self):
        self.assertEqual(IPUtils.mask_ip("192.168.1.50"), "192.168.1.***")
        self.assertEqual(IPUtils.mask_ip("10.0.0.123"), "10.0.0.***")


class TestBlacklistManager(unittest.TestCase):
    def test_dunders(self):
        bm = BlacklistManager(["192.168.1.50", "10.0.0.1"])
        self.assertEqual(len(bm), 2)
        self.assertIn("192.168.1.50", bm)
        self.assertNotIn("8.8.8.8", bm)

        bm.add_ip("8.8.8.8")
        self.assertEqual(len(bm), 3)
        self.assertIn("8.8.8.8", bm)

        bm.remove_ip("10.0.0.1")
        self.assertEqual(len(bm), 2)
        self.assertNotIn("10.0.0.1", bm)


class TestAuditLogger(unittest.TestCase):
    def test_audit_logger_decorator(self):
        @audit_logger
        def detect_attack(ip: str) -> bool:
            return ip == "192.168.1.50"

        res_true = detect_attack("192.168.1.50")
        self.assertTrue(res_true)

        res_false = detect_attack("1.1.1.1")
        self.assertFalse(res_false)

    def test_audit_logger_handles_exception(self):
        @audit_logger
        def failing_func():
            raise RuntimeError("DB connection failed")

        result = failing_func()
        self.assertFalse(result)


if __name__ == "__main__":
    unittest.main()
