# /// script
# requires-python = ">=3.11"
# ///
"""后台任务（detach）脚本构造与解析的离线用例：裸 python，不装 paramiko 也不碰网络。

    python test_ssh_jobs.py
"""

from __future__ import annotations

import shlex
import unittest

import ssh_jobs as J

JID = "job-1a2b3c4d-abcd"
JID2 = "job-0000000000-0000"


class JobId(unittest.TestCase):
    def test_generated_shape(self):
        for _ in range(20):
            self.assertRegex(J.new_job_id(), J.JOB_ID_RE)

    def test_two_calls_differ(self):
        self.assertNotEqual(J.new_job_id(1000.0), J.new_job_id(1000.0))

    def test_rejects_dangerous_ids(self):
        # id 会拼进脚本和 SFTP 路径，只做白名单，不转义
        for bad in ("", "job", "job-abc-0000", "job-ABC123-abcd", "job-123456-abcd extra",
                    "job-123456-zzzz", "../../etc", "job-1a2b3c4d-abcd;rm -rf /",
                    "job-123456789012345-abcd"):
            with self.assertRaises(ValueError, msg=bad):
                J.validate_job_id(bad)


class StartScript(unittest.TestCase):
    def test_detached_launch_shape(self):
        s = J.build_start_script(JID, "echo hi", "", 7, 8)
        self.assertIn("nohup $S sh -c", s)
        self.assertIn("command -v setsid", s)
        self.assertIn('> "$J/out" 2>&1 < /dev/null &', s)
        self.assertIn('echo "STARTED $(cat "$J/pid")"', s)

    def test_command_is_quoted_not_pasted(self):
        evil = "echo 'x' ; rm -rf / ; #"
        s = J.build_start_script(JID, evil, "", 7, 8)
        self.assertIn(shlex.quote(evil), s)
        self.assertNotIn("; rm -rf / ;", s.replace(shlex.quote(evil), ""))

    def test_tilde_dir_is_expanded_inside_the_wrapper(self):
        # 引号里的波浪号不展开：`cd -- "~/x"` 必失败，所以 wrapper 里显式换 $HOME
        s = J.build_start_script(JID, "true", "~/sub dir", 7, 8)
        self.assertIn('"$HOME/${2#\\~/}"', s)
        self.assertIn(shlex.quote("~/sub dir"), s)

    def test_retention_and_cap_come_from_args(self):
        s = J.build_start_script(JID, "true", "", 30, 3)
        self.assertIn("-mtime +30", s)
        self.assertIn('[ "$BUSY" -ge 3 ]', s)
        self.assertIn('echo "BUSY $BUSY"', s)

    def test_busy_scan_skips_non_job_dirs(self):
        s = J.build_start_script(JID, "true", "", 7, 8)
        self.assertIn('case "$id" in job-*) ;; *) continue;; esac', s)
        self.assertIn('if [ ! -f "$d/exit" ] && [ ! -f "$d/killed" ]', s)

    def test_dir_file_only_written_when_directory_given(self):
        self.assertNotIn('"$J/dir"', J.build_start_script(JID, "true", "", 7, 8))
        self.assertIn('> "$J/dir"', J.build_start_script(JID, "true", "/var/log", 7, 8))


class OtherScripts(unittest.TestCase):
    def test_state_reports_kv_lines(self):
        s = J.build_state_script(JID)
        for key in ("state=", "code=", "pid=", "started=", "now=", "out_bytes=", "command="):
            self.assertIn(f'echo "{key}', s)
        self.assertIn("job_is_ours", s)
        self.assertIn(f"ID={JID}", s)

    def test_kill_sigterm_then_sigkill_and_marker(self):
        s = J.build_kill_script(JID)
        self.assertIn('kill -s TERM -- "-$pid"', s)
        self.assertIn('kill -s KILL -- "-$pid"', s)
        self.assertIn('touch "$J/killed"', s)
        self.assertIn("kill_tree", s)

    def test_list_rows_are_pipe_delimited(self):
        s = J.build_list_script(20)
        self.assertIn('echo "$ID|$state|$code|', s)
        self.assertIn('[ "$n" -gt 20 ]', s)

    def test_no_heredoc_in_any_script(self):
        for s in (J.build_state_script(JID), J.build_kill_script(JID), J.build_list_script(5)):
            self.assertNotIn("<<", s)


class Parsers(unittest.TestCase):
    def test_kv_values_keep_equals_signs(self):
        kv = J.parse_kv("state=running\ncode=\npid=123\n\ncommand=echo a=b|c\n")
        self.assertEqual(kv["state"], "running")
        self.assertEqual(kv["code"], "")
        self.assertEqual(kv["command"], "echo a=b|c")

    def test_start_outputs(self):
        self.assertEqual(J.parse_start("STARTED 4321\n"), {"result": "started", "pid": 4321})
        self.assertEqual(J.parse_start("BUSY 8\n"), {"result": "busy", "busy": 8})
        self.assertEqual(J.parse_start("NOPID\n"), {"result": "nopid"})
        self.assertEqual(J.parse_start(""), {"result": "unknown"})

    def test_list_rows(self):
        rows = J.parse_list(f"{JID}|exited|0|1791973983\n{JID2}|running||\n(none)\n")
        self.assertEqual(rows[0], {"job_id": JID, "state": "exited", "exit_code": 0, "started": 1791973983})
        self.assertEqual(rows[1]["state"], "running")
        self.assertIsNone(rows[1]["exit_code"])
        self.assertEqual(len(rows), 2, "非 job- 开头的行不该进结果")

    def test_list_ignores_foreign_lines(self):
        self.assertEqual(J.parse_list("rm -rf /|x|0|1\n"), [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
