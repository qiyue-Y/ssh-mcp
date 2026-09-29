# /// script
# requires-python = ">=3.11"
# ///
"""自杀清单守卫的离线用例：裸 python 即可，不需要 paramiko 和 mcp。

清单实际内容取自仓库的 policy.json，所以改条目时这里会跟着红/绿。

    python test_ssh_guard.py
"""

from __future__ import annotations

import json
import unittest
from pathlib import Path

import ssh_guard as G

HERE = Path(__file__).resolve().parent
CFG = G.load_guard(json.loads((HERE / "policy.json").read_text(encoding="utf-8")))


def blocked(command: str) -> bool:
    return G.check(command, CFG) is not None


class AssertBlockedMixin:
    def assertBlocked(self, *commands: str) -> None:
        for c in commands:
            self.assertTrue(blocked(c), f"应当拦下：{c}")

    def assertPasses(self, *commands: str) -> None:
        for c in commands:
            self.assertFalse(blocked(c), f"不该拦：{c}")


class KilllistHits(AssertBlockedMixin, unittest.TestCase):
    def test_disk_destroy(self):
        self.assertBlocked(
            "mkfs.ext4 /dev/sda1",
            "mkfs -t xfs /dev/vdb",
            "wipefs -a /dev/sda",
            "dd if=/dev/zero of=/dev/sda bs=1M",
            "parted /dev/sda rm 1",
            "fdisk /dev/sda",
        )

    def test_power_off_and_lockout(self):
        self.assertBlocked(
            "shutdown -h now",
            "reboot",
            "halt",
            "poweroff",
            "init 0",
            "init 6",
            "systemctl stop sshd",
            "systemctl disable ssh",
            "systemctl stop firewalld",
            "iptables -F",
            "nft flush ruleset",
            "ufw disable",
        )

    def test_account_and_mode(self):
        self.assertBlocked("userdel -r app", "groupdel docker", "passwd root", "chmod 777 /", "chown -R root /")

    def test_rm_Recursive_on_top_level_dir(self):
        self.assertBlocked("rm -rf /", "rm -rf /*", "rm -fr /etc", "rm -r /var", "rm -Rf /", "rm --recursive --force /")

    def test_write_that_breaks_login(self):
        self.assertBlocked(
            "cat x > /root/.ssh/authorized_keys",
            "echo key >> ~/.ssh/authorized_keys",
            "tee /etc/fstab",
        )


class EquivalenceNormalized(AssertBlockedMixin, unittest.TestCase):
    """写法变体必须归一后再比，否则清单形同虚设。"""

    def test_path_spellings(self):
        self.assertBlocked("rm -rf //", "rm -rf /./", "rm -rf /etc/", "rm -rf /*")

    def test_octal_mode_equivalence(self):
        self.assertBlocked("chmod 0777 /")

    def test_separator_without_spaces_splits(self):
        # shlex 会把 `;` 粘回前一个 token，不分段就只能看见 uptime
        self.assertBlocked("uptime;rm -rf /", "df -h|reboot", "ps aux&&mkfs /dev/sda1")

    def test_env_assignment_prefix_skipped(self):
        self.assertBlocked("LC_ALL=C reboot", "FOO=bar DEBIAN_FRONTEND=noninteractive shutdown")

    def test_redirect_and_fd_spellings(self):
        self.assertBlocked("echo k 1>/root/.ssh/authorized_keys", "echo k >/etc/sudoers")


class BenignCommandsPass(AssertBlockedMixin, unittest.TestCase):
    def test_second_level_paths_are_not_top_level(self):
        self.assertPasses("rm -rf /tmp/build", "rm -rf /var/log/app/*.log", "rm -rf ./node_modules")

    def test_systemctl_subcommands_that_keep_us_connected(self):
        self.assertPasses("systemctl restart nginx", "systemctl status sshd", "systemctl enable nfs-server")

    def test_innocuous_chmod_and_fdisk_reads(self):
        self.assertPasses("chmod 777 /tmp/x", "fdisk -l", "df -h")

    def test_fd_dup_is_not_a_write(self):
        self.assertPasses("make -j8 2>&1 | tee /tmp/build.log", "grep x /etc/shadow 2>/dev/null")

    def test_quoted_separators_are_not_separators(self):
        self.assertPasses("echo 'a;b'", "awk -F';' '{print $1}' /etc/passwd")

    def test_everyday_admin_work(self):
        self.assertPasses(
            "apt install -y nginx",
            "pip install torch",
            "docker system prune -af",
            "kubectl delete pod x",
            "useradd bob",
            "mount /dev/sdb1 /mnt/data",
            "crontab -r",
            "history -c",
            "sudo systemctl restart sshd",
        )


class DeliberatelyNotCaught(unittest.TestCase):
    """解除权限控制后明确不再防的形态 —— 钉在用例里，别当成已防住。

    原 rw 黑名单靠「包装器剥壳 + 解释器 -c 递归判定」防这些，那套是纯静态分析，
    防得住手滑防不住蓄意，而代价是每条正常命令都可能被误杀。现在不要了。
    """

    def test_wrapper_shell_and_interpreter_indirection(self):
        for c in (
            "nohup rm -rf /",
            "env FOO=1 reboot",
            "timeout 5 mkfs /dev/sda",
            "bash -c 'rm -rf /'",
            "python -c \"import os;os.system('reboot')\"",
            "$(echo rm) -rf /",
            "R=/; rm -rf $R",
        ):
            self.assertFalse(blocked(c), f"设计上放行（防不住静态切片看不见的东西）：{c}")


class GuardScope(unittest.TestCase):
    """查不查这张表：root 恒查，非 root 看 guarded_hosts 点没点名。"""

    CFG = G.GuardConfig(kill_prefixes=CFG.kill_prefixes, guarded_hosts=frozenset({"named"}))

    def test_root_always_guarded(self):
        self.assertTrue(G.applies(True, "anything", self.CFG))

    def test_nonroot_guarded_only_when_named(self):
        self.assertTrue(G.applies(False, "named", self.CFG))
        self.assertFalse(G.applies(False, "unlisted", self.CFG))

    def test_nonroot_host_still_blocked_when_named(self):
        """非 root 只要点了名，判定内容与 root 主机完全一致。"""
        self.assertTrue(G.check("rm -rf /", self.CFG) is not None)

    def test_guarded_hosts_loaded_from_policy_json(self):
        raw = json.loads((HERE / "policy.json").read_text(encoding="utf-8"))
        loaded = G.load_guard(raw)
        self.assertEqual(loaded.guarded_hosts, frozenset(raw.get("guarded_hosts") or []))
        # 清单条目不能因为加了 guarded_hosts 就掉
        self.assertEqual(len(loaded.kill_prefixes), len(CFG.kill_prefixes))


class ConfigWiring(unittest.TestCase):
    def test_killlist_loaded_from_policy_json(self):
        self.assertGreaterEqual(len(CFG.kill_prefixes), 20)

    def test_limits_parsed(self):
        self.assertEqual(CFG.idle_timeout_s, 30)
        self.assertEqual(CFG.max_duration_s, 300)
        self.assertEqual(CFG.max_output_bytes, 8388608)

    def test_unparsable_command_is_not_blocked(self):
        # 引号都没闭合，远端 shell 自己也走不到执行
        self.assertFalse(blocked("echo 'unclosed"))

    def test_hit_carries_the_rule_text(self):
        hit = G.check("systemctl stop sshd", CFG)
        self.assertIsNotNone(hit)
        self.assertIn("systemctl stop sshd", hit.rule)


if __name__ == "__main__":
    unittest.main(verbosity=2)
