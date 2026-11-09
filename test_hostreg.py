# /// script
# requires-python = ">=3.11"
# ///
"""hostreg 的离线用例：纯 stdlib，不碰网络、不 import paramiko。

    python test_hostreg.py
"""

from __future__ import annotations

import base64
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

import hostreg as R


def tmpdir() -> Path:
    return Path(tempfile.mkdtemp(prefix="hostreg-test-"))


def entry(**over) -> dict:
    base = {
        "address": "10.0.0.10", "port": 22, "username": "deploy",
        "auth": "password", "password": "secret", "hostKey": "SHA256:AAAAAAAA",
    }
    base.update(over)
    return base


def key_blob(text: str) -> str:
    return base64.b64encode(hashlib.sha256(text.encode()).digest()).decode()


class Validation(unittest.TestCase):
    def test_good_entry_has_no_errors(self):
        errors, warnings = R.validate("100", entry(), set(), is_new=True)
        self.assertEqual(errors, [])
        self.assertEqual(warnings, [])

    def test_bad_alias(self):
        self.assertTrue(R.validate("_note", entry(), set())[0])
        self.assertTrue(R.validate("has space", entry(), set())[0])
        self.assertTrue(R.validate("dup", entry(), {"dup"})[0])
        self.assertEqual(R.validate("dup", entry(), {"dup"}, is_new=False)[0], [], "更新已有条目不算重名")

    def test_bad_address_and_port(self):
        self.assertTrue(R.validate("a", entry(address=""), set())[0])
        self.assertTrue(R.validate("a", entry(address="10 .0.0.1"), set())[0])
        self.assertTrue(R.validate("a", entry(port=0), set())[0])
        self.assertTrue(R.validate("a", entry(port=70000), set())[0])
        self.assertTrue(R.validate("a", entry(port="abc"), set())[0])

    def test_bad_hostkey_shape(self):
        self.assertTrue(R.validate("a", entry(hostKey="SHA256:AAA="), set())[0])
        self.assertTrue(R.validate("a", entry(hostKey="md5:aa:bb"), set())[0])
        self.assertEqual(R.validate("a", entry(hostKey=""), set())[0], [])
        self.assertTrue(R.validate("a", entry(hostKey=""), set())[1], "空指纹是警告不是错误")

    def test_empty_password_is_warning_for_new_entry(self):
        errors, warnings = R.validate("a", entry(password=""), set(), is_new=True)
        self.assertEqual(errors, [])
        self.assertTrue(warnings)
        errors, warnings = R.validate("a", entry(password=""), set(), is_new=False)
        self.assertEqual(errors, [])
        self.assertFalse(any("口令为空" in w for w in warnings), "更新时留空表示沿用旧口令")

    def test_key_auth_missing_key_file_is_warning(self):
        errors, warnings = R.validate("a", entry(auth="key", key_path="Z:\\no\\key"), set())
        self.assertEqual(errors, [])
        self.assertTrue(any("key_path" in w for w in warnings))


class SaveAndBackup(unittest.TestCase):
    def setUp(self):
        self.dir = tmpdir()
        self.path = self.dir / "hosts.json"

    def test_atomic_write_and_comment_preserved(self):
        self.path.write_text(json.dumps({"_说明": "手工注释", "100": entry()}, ensure_ascii=False), encoding="utf-8")
        reg = R.Registry(self.path)
        reg.upsert("66", entry(address="10.0.0.66"))
        backup = reg.save()
        data = json.loads(self.path.read_text(encoding="utf-8"))
        self.assertEqual(data["_说明"], "手工注释")
        self.assertEqual(data["100"]["address"], "10.0.0.10")
        self.assertEqual(data["66"]["address"], "10.0.0.66")
        self.assertTrue(backup.startswith("hosts.json.bak-"))
        self.assertFalse((self.dir / "hosts.json.tmp").exists(), "临时文件不能留下")

    def test_unknown_fields_survive_update(self):
        self.path.write_text(json.dumps({"100": {**entry(), "future_field": "keep-me"}}), encoding="utf-8")
        reg = R.Registry(self.path)
        reg.upsert("100", entry(username="ops"))
        reg.save()
        data = json.loads(self.path.read_text(encoding="utf-8"))
        self.assertEqual(data["100"]["future_field"], "keep-me")
        self.assertEqual(data["100"]["username"], "ops")

    def test_password_empty_keeps_old_value(self):
        self.path.write_text(json.dumps({"100": entry(password="old-secret")}), encoding="utf-8")
        reg = R.Registry(self.path)
        reg.upsert("100", entry(password="", username="ops"))
        reg.save()
        data = json.loads(self.path.read_text(encoding="utf-8"))
        self.assertEqual(data["100"]["password"], "old-secret")
        self.assertEqual(data["100"]["username"], "ops")

    def test_password_filled_replaces(self):
        self.path.write_text(json.dumps({"100": entry(password="old")}), encoding="utf-8")
        reg = R.Registry(self.path)
        reg.upsert("100", entry(password="new"))
        reg.save()
        self.assertEqual(json.loads(self.path.read_text(encoding="utf-8"))["100"]["password"], "new")

    def test_backups_are_pruned(self):
        self.path.write_text(json.dumps({"100": entry()}), encoding="utf-8")
        for n in range(R.BACKUP_KEEP + 4):
            reg = R.Registry(self.path)
            reg.upsert("100", entry(username=f"u{n}"))
            reg.save()
        baks = list(self.dir.glob("hosts.json.bak-*"))
        self.assertLessEqual(len(baks), R.BACKUP_KEEP)

    def test_remove_and_flag(self):
        self.path.write_text(json.dumps({"100": entry()}), encoding="utf-8")
        reg = R.Registry(self.path)
        self.assertTrue(reg.set_flag("100", "disabled", True))
        self.assertFalse(reg.set_flag("100", "purpose", True), "只允许布尔能力位")
        self.assertTrue(reg.remove("100"))
        self.assertFalse(reg.remove("100"))
        reg.save()
        self.assertEqual(json.loads(self.path.read_text(encoding="utf-8")), {})

    def test_broken_json_refuses_to_save(self):
        self.path.write_text("{ this is not json", encoding="utf-8")
        reg = R.Registry(self.path)
        self.assertFalse(reg.writable)
        with self.assertRaises(R.HostregError):
            reg.save()
        self.assertEqual(self.path.read_text(encoding="utf-8"), "{ this is not json", "坏文件不能被覆盖")

    def test_missing_file_is_empty_registry(self):
        reg = R.Registry(self.path)
        self.assertTrue(reg.writable)
        self.assertEqual(reg.entries(), {})


class Scan(unittest.TestCase):
    def setUp(self):
        self.dir = tmpdir()

    def test_known_hosts_parses_and_ranks(self):
        blob_ed = key_blob("ed25519")
        blob_rsa = key_blob("rsa")
        content = (
            f"10.0.0.5 ssh-ed25519 {blob_ed}\n"
            f"10.0.0.5 ssh-rsa {blob_rsa}\n"
            f"[10.0.0.6]:2222 ecdsa-sha2-nistp256 {blob_ed}\n"
            "|1|hashed|host ssh-ed25519 " + blob_ed + "\n"
        )
        path = self.dir / "known_hosts"
        path.write_text(content, encoding="utf-8")
        hosts, hashed = R.read_known_hosts(path)
        self.assertEqual(hashed, 1)
        self.assertEqual(set(hosts), {("10.0.0.5", 22), ("10.0.0.6", 2222)})
        self.assertEqual(R.fingerprint(blob_ed), hosts[("10.0.0.5", 22)]["ssh-ed25519"])

    def test_ssh_config_skips_wildcards(self):
        path = self.dir / "config"
        path.write_text(
            "Host web\n  HostName 10.0.0.7\n  User deploy\n  Port 2222\n"
            "Host *\n  User nobody\n"
            "Host db\n  HostName 10.0.0.8\n",
            encoding="utf-8",
        )
        cfg = R.read_ssh_config(path)
        self.assertEqual(cfg["web"], {"hostname": "10.0.0.7", "user": "deploy", "port": "2222"})
        self.assertNotIn("*", cfg)

    def test_build_candidates_marks_existing_and_conflicts(self):
        blob = key_blob("ed")
        connected = {("10.0.0.5", 22): {"ssh-ed25519": R.fingerprint(blob)},
                     ("10.0.0.6", 22): {"ssh-ed25519": R.fingerprint(blob)}}
        config = {"web": {"hostname": "10.0.0.6", "user": "ops"}}
        raw = {"_说明": "x", "5": {"address": "10.0.0.5", "port": 22}}
        by_addr = {c.entry["address"]: c for c in R.build_candidates(raw, connected, config)}
        self.assertFalse(by_addr["10.0.0.5"].importable, "已在清单里的地址要标不可导入")
        self.assertTrue(any("已在清单里" in r for r in by_addr["10.0.0.5"].reasons))
        self.assertNotEqual(by_addr["10.0.0.5"].alias, "5", "别名冲突时退回用地址")
        self.assertTrue(by_addr["10.0.0.6"].importable)
        self.assertEqual(by_addr["10.0.0.6"].entry["username"], "ops")
        self.assertEqual(by_addr["10.0.0.6"].entry["hostKey"], R.fingerprint(blob))

    def test_candidate_without_fingerprint_is_noted(self):
        cands = R.build_candidates({}, {}, {"only": {"hostname": "10.0.0.9", "user": "x"}})
        self.assertEqual(len(cands), 1)
        self.assertTrue(any("探测" in n for n in cands[0].notes))
        self.assertTrue(cands[0].importable, "缺指纹只是提醒，可以导入后再探测")


if __name__ == "__main__":
    unittest.main(verbosity=2)
