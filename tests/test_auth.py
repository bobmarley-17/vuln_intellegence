"""Tests for the dashboard login accounts: password hashing/verification,
duplicate handling, and enable/disable."""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from modules.cache import DuplicateUserError, VulnCache


class UserAuthTests(unittest.TestCase):
    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self.cache = VulnCache(str(Path(self._tmpdir.name) / "cache.db"))

    def tearDown(self):
        self._tmpdir.cleanup()

    def test_create_user_rejects_duplicate_username(self):
        self.cache.create_user("alice", "correct-horse-battery-staple")
        with self.assertRaises(DuplicateUserError):
            self.cache.create_user("alice", "another-password")

    def test_password_is_hashed_not_stored_in_plaintext(self):
        self.cache.create_user("alice", "correct-horse-battery-staple")
        row = self.cache.get_user_by_username("alice")
        self.assertNotEqual(row["password_hash"], "correct-horse-battery-staple")
        self.assertTrue(row["password_hash"])

    def test_verify_user_password_accepts_correct_credentials(self):
        self.cache.create_user("alice", "correct-horse-battery-staple")
        row = self.cache.verify_user_password("alice", "correct-horse-battery-staple")
        self.assertIsNotNone(row)
        self.assertEqual(row["username"], "alice")

    def test_verify_user_password_rejects_wrong_password(self):
        self.cache.create_user("alice", "correct-horse-battery-staple")
        self.assertIsNone(self.cache.verify_user_password("alice", "wrong-password"))

    def test_verify_user_password_rejects_unknown_user(self):
        self.assertIsNone(self.cache.verify_user_password("nobody", "whatever"))

    def test_disabled_user_cannot_log_in(self):
        self.cache.create_user("alice", "correct-horse-battery-staple")
        self.assertTrue(self.cache.set_user_active("alice", False))
        self.assertIsNone(self.cache.verify_user_password("alice", "correct-horse-battery-staple"))

    def test_re_enabled_user_can_log_in_again(self):
        self.cache.create_user("alice", "correct-horse-battery-staple")
        self.cache.set_user_active("alice", False)
        self.cache.set_user_active("alice", True)
        self.assertIsNotNone(self.cache.verify_user_password("alice", "correct-horse-battery-staple"))

    def test_set_user_active_returns_false_for_unknown_user(self):
        self.assertFalse(self.cache.set_user_active("nobody", False))

    def test_update_last_login_sets_timestamp(self):
        user_id = self.cache.create_user("alice", "correct-horse-battery-staple")
        self.assertIsNone(self.cache.get_user_by_id(user_id)["last_login_at"])
        self.cache.update_last_login(user_id)
        self.assertIsNotNone(self.cache.get_user_by_id(user_id)["last_login_at"])

    def test_list_users_does_not_leak_password_hash(self):
        self.cache.create_user("alice", "correct-horse-battery-staple")
        users = self.cache.list_users()
        self.assertEqual(len(users), 1)
        self.assertNotIn("password_hash", users[0])


if __name__ == "__main__":
    unittest.main()
