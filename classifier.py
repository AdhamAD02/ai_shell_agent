from __future__ import annotations
 
import logging
import re
 
from .models import ClassificationResult, RiskLevel
 
log = logging.getLogger(__name__)


_READ_ONLY_CMDS: frozenset[str] = frozenset({
    "ls", "la", "ll", "cat", "bat", "less", "more", "head", "tail",
    "ps", "top", "htop", "btop", "atop",
    "df", "du", "free", "vmstat", "iostat", "mpstat", "sar",
    "ss", "netstat", "ip", "ifconfig", "ping", "traceroute", "nslookup", "dig",
    "journalctl", "dmesg", "systemctl",
    "id", "whoami", "uname", "hostname", "uptime", "date", "cal",
    "which", "whereis", "locate", "find",  # find is read-only unless -exec rm
    "file", "stat", "lsof", "lsblk", "lscpu", "lsusb", "lspci",
    "echo", "printf", "env", "printenv", "set",
    "history", "alias", "type",
    "wc", "sort", "uniq", "grep", "egrep", "fgrep", "rg", "ag",
    "awk", "sed",   # read-only unless redirecting output
    "cut", "tr", "paste", "join", "diff", "cmp",
    "md5sum", "sha1sum", "sha256sum",
    "git", "svn",   # default is read
    "man", "info", "help", "whatis", "apropos",
    "python3", "python", "node", "ruby",  # running scripts
})
 
_REVERSIBLE_CMDS: frozenset[str] = frozenset({
    "mv", "cp", "ln", "mkdir", "rmdir", "touch",
    "chmod", "chown", "chgrp",
    "tar", "gzip", "gunzip", "bzip2", "bunzip2", "xz", "unxz", "zip", "unzip",
    "systemctl",   # restart/reload only
    "service",
    "apt", "apt-get", "yum", "dnf", "pacman", "snap", "flatpak",
    "pip", "pip3", "npm", "yarn", "cargo", "go",
    "git",   # commit/push/pull
    "crontab",
    "useradd", "usermod", "groupadd",
    "mount", "umount",
    "sysctl",
    "ufw", "firewall-cmd",
})
 
_DESTRUCTIVE_CMDS: frozenset[str] = frozenset({
    "rm", "rmdir",
    "dd", "shred", "wipe", "wipefs", "secure-delete",
    "mkfs", "mke2fs", "mkswap", "fdisk", "gdisk", "parted", "cfdisk",
    "format",
    "truncate",
    "iptables", "ip6tables", "nftables",
    "passwd", "chpasswd",
    "userdel", "groupdel",
    "pkill", "killall", "kill",
    "reboot", "shutdown", "halt", "poweroff", "init",
    "> /dev/",   # redirect to device
    "eval",
})
 
# critical system paths. reversible ops on these become destructive
_CRITICAL_PATHS: tuple[str, ...] = (
    "/etc", "/usr", "/bin", "/sbin", "/lib", "/lib64",
    "/boot", "/sys", "/proc", "/dev",
    "/root", "/var/lib",
)
 

_ESCALATION_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"curl\s+.*\|\s*(bash|sh|zsh|python|perl|ruby)"), "remote_code_exec"),
    (re.compile(r"wget\s+.*-O\s*-\s*\|\s*(bash|sh)"),            "remote_code_exec"),
    (re.compile(r"\beval\b"),                                      "eval_usage"),
    (re.compile(r"\$\(.*\)"),                                      "command_substitution"),
    (re.compile(r">\s*/dev/"),                                     "device_write"),
    (re.compile(r">\s*/etc/"),                                     "system_config_write"),
    (re.compile(r"sudo\s+"),                                       "sudo_escalation"),
    (re.compile(r"--force|-f\b"),                                  "force_flag"),
    (re.compile(r"-r\b|-R\b"),                                     "recursive_flag"),
    (re.compile(r"\*"),                                            "wildcard"),
]
 
_SYSTEMCTL_WRITE_SUBCMDS: frozenset[str] = frozenset({
    "stop", "disable", "mask", "kill", "reset-failed",
})
 
_SYSTEMCTL_DESTRUCTIVE_SUBCMDS: frozenset[str] = frozenset({
    "mask",
})


class RiskClassifier:

    def classify(self , command: str) -> ClassificationResult:

        command = command.strip()
        
        if not command:
            return ClassificationResult(
                level = RiskLevel.READ_ONLY,
                reason= "Empty command"
            )

        result = self._rule_based(command)

        if result is not None:
            return result
        
        # rule based failed to classify the command so move the command to llm classification

        log.debug("Rule-based inconclusive for %r, trying LLM.", command)

        return self.llm_classify(command)




    def _rule_based(self , command: str) -> ClassificationResult | None:
        pass 



    def llm_classify(self , command: str) -> ClassificationResult:
        pass