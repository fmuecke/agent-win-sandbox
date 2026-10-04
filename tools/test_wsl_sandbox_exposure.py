#!/usr/bin/env python3
"""Native, non-elevating Linux/WSL exposure assessment; Python 3.9+ stdlib only."""
import sys
sys.dont_write_bytecode = True
import argparse
import configparser
import errno
import ipaddress
import itertools
import json
import math
import multiprocessing
import os
from pathlib import Path
import re
import resource
import socket
import stat
import time
from datetime import datetime, timezone

VERSION = "1.0.0"
PROFILE = "wsl-inside-exposure-1"
DIMENSIONS = ("Reach", "Authority", "Containment", "Monitoring")
# Fixed registry: positive protection criteria, not number of findings.
REGISTRY = {
    "host_files": ("Reach", True, "Windows/shared filesystem access limited"),
    "secrets": ("Reach", True, "Accessible credential material limited"),
    "process_memory": ("Reach", True, "Foreign-user process memory access limited"),
    "network": ("Reach", True, "Egress and lateral routes limited"),
    "gui": ("Reach", False, "GUI/audio/clipboard bridges limited"),
    "privileges": ("Authority", True, "Linux identity/capability authority limited"),
    "delegation": ("Authority", True, "Broker and delegated authority limited"),
    "remote_tools": ("Authority", True, "Remote and agent tool authority limited"),
    "handoff": ("Authority", True, "Higher-privilege execution consumers protected"),
    "interop": ("Containment", True, "Windows process-launch bridge limited"),
    "control_integrity": ("Containment", True, "Restriction/bootstrap controls protected"),
    "kernel_controls": ("Containment", False, "Kernel hardening mechanisms present"),
    "lifecycle": ("Containment", True, "Child/resource/lifecycle boundary established"),
    "host_boundary": ("Containment", True, "Host isolation established independently"),
    "action_logs": ("Monitoring", True, "Action coverage and attribution established"),
    "log_integrity": ("Monitoring", True, "Logs protected against agent tampering"),
    "external_collection": ("Monitoring", True, "Independent collection established"),
}
TOKEN_PATTERNS = {
    "github_token": re.compile(r"\b(?:github_pat_[A-Za-z0-9_]{20,}|gh[pousr]_[A-Za-z0-9]{20,})\b"),
    "provider_token": re.compile(r"\b(?:sk-(?:proj-)?[A-Za-z0-9_-]{20,}|xox[baprs]-[A-Za-z0-9-]{15,})\b"),
    "aws_access_key_id": re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    "private_key": re.compile(r"-----BEGIN (?:OPENSSH |RSA |EC |DSA |ENCRYPTED )?PRIVATE KEY-----"),
    "secret_assignment": re.compile(r'''(?im)["']?(?:api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|password|passwd|secret[_-]?key|aws_secret_access_key)["']?\s*[:=]\s*["']?([^\s"',;}{]{8,})'''),
}
SECRET_ENV = re.compile(r"(?:TOKEN|SECRET|PASSWORD|PASSWD|API_KEY|APIKEY|PRIVATE_KEY|CREDENTIAL)", re.I)
REMOTE_FS = {"cifs", "smb3", "nfs", "nfs4", "sshfs", "fuse.sshfs", "9p", "drvfs", "virtiofs", "fuse.rclone"}
TEXT_EXT = {".json", ".yaml", ".yml", ".toml", ".ini", ".conf", ".config", ".env", ".txt", ".xml", ".properties", ".tf", ".tfvars", ".sh", ".py", ".js", ".ts", ".ps1", ".pem", ".key"}
KNOWN_NAMES = {"credentials", "config", "id_rsa", "id_ed25519", "id_ecdsa", ".git-credentials", ".npmrc", ".pypirc", ".netrc", "kubeconfig", ".env"}


def error_kind(exc):
    return {errno.EACCES: "permission_denied", errno.EPERM: "permission_denied",
            errno.ENOENT: "absent_or_disappeared", errno.ELOOP: "symlink_rejected",
            errno.ECONNREFUSED: "connection_refused", errno.ETIMEDOUT: "timeout"}.get(
                getattr(exc, "errno", None), type(exc).__name__)


def read_small(path, maximum=262144):
    """Trusted local kernel/config inventory only; never serialize raw content."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                return None, "not_regular"
            data = os.read(fd, maximum + 1)
            if len(data) > maximum:
                return None, "size_limit"
            return data.decode("utf-8", errors="replace"), None
        finally:
            os.close(fd)
    except OSError as exc:
        return None, error_kind(exc)


def parse_status(text):
    return dict(line.split(":", 1) for line in (text or "").splitlines() if ":" in line)


def unescape_mount(value):
    return re.sub(r"\\([0-7]{3})", lambda m: chr(int(m[1], 8)), value)


def parse_mounts(text):
    result = []
    for line in text.splitlines():
        left, right = line.split(" - ", 1)
        a, b = left.split(), right.split()
        if len(a) < 6 or len(b) < 3:
            raise ValueError("malformed_mountinfo")
        # Never report raw source/superoptions: CIFS URLs may contain credentials.
        fs, superopts = b[0], b[2]
        windows = fs == "drvfs" or (fs == "9p" and "drvfs" in superopts.lower())
        result.append({"target": unescape_mount(a[4]), "fs": fs,
                       "readonly": "ro" in a[5].split(","), "windows": windows,
                       "remote": (fs in REMOTE_FS and not windows) or (windows and (unescape_mount(b[1]).startswith("\\\\") or "unc" in superopts.lower())),
                       "shared": windows or fs in REMOTE_FS or unescape_mount(a[4]).startswith("/mnt/wsl")})
    return result


def beneath(path, root):
    return path == root or path.startswith(root.rstrip("/") + "/")


def mount_for(path, mounts):
    candidates = [m for m in mounts if beneath(path, m["target"])]
    return max(candidates, key=lambda m: len(m["target"])) if candidates else None


def access(path, mode):
    try:
        return os.access(path, mode, effective_ids=True)
    except (OSError, NotImplementedError):
        return None


def path_probe(path):
    """No write opens. Absence and errors remain distinct from an access denial."""
    try:
        s = os.stat(path)
    except OSError as exc:
        return {"path": path, "state": error_kind(exc)}
    return {"path": path, "state": "present", "kind": "socket" if stat.S_ISSOCK(s.st_mode)
            else "directory" if stat.S_ISDIR(s.st_mode) else "file" if stat.S_ISREG(s.st_mode) else "device_or_other",
            "uid": s.st_uid, "read_permission": access(path, os.R_OK),
            "write_permission": access(path, os.W_OK), "method": "effective_access_permission_analysis"}


def score(criteria, critical=False):
    dims = {}
    low = high = coverage = 0.0
    for dim in DIMENSIONS:
        rows = [v for v in criteria.values() if v["dimension"] == dim and v["outcome"] != "not_applicable"]
        n = len(rows)
        met = sum(v["outcome"] == "met" for v in rows)
        unknown = sum(v["outcome"] == "unknown" for v in rows)
        lo = 25 * met / n if n else 0
        hi = 25 * (met + unknown) / n if n else 25
        cov = 100 * (n - unknown) / n if n else 0
        dims[dim] = {"lower": round(lo, 2), "upper": round(hi, 2), "coverage_percent": round(cov, 1)}
        low += lo
        high += hi
        coverage += cov / 4
    essential = [k for k, v in criteria.items() if v["essential"] and v["outcome"] == "unknown"]
    lo, hi = math.floor(low + 1e-9), math.ceil(high - 1e-9)
    verdict = "Critical exposure" if critical else "Incomplete" if essential else "Weak" if lo < 40 else "Partial" if lo < 70 else "Bounded within tested scope"
    return {"lower": min(lo, 39) if critical else lo, "upper": min(hi, 39) if critical else hi,
            "coverage_percent": round(coverage, 1), "dimensions": dims, "essential_unknowns": essential, "verdict": verdict}


class Checker:
    def __init__(self, args):
        self.args = args
        self.criteria = {k: {"dimension": d, "essential": e, "description": t,
                             "outcome": "unknown", "reason": "Not established from this context"}
                         for k, (d, e, t) in REGISTRY.items()}
        self.findings = []
        self.inventory = {}
        self.errors = []
        self.redactions = set()
        self.mounts = []
        self.wsl = False

    def outcome(self, key, value, reason):
        self.criteria[key].update(outcome=value, reason=reason)

    def finding(self, key, target, capability, result, method, impact, severity="medium"):
        self.findings.append(dict(check_id=key, target=target, capability=capability, result=result,
                                  method=method, impact=impact, severity=severity))

    def inventory_text(self, path, limit=262144):
        data, err = read_small(path, limit)
        if err:
            self.errors.append({"target": path, "category": err})
        return data

    def probe(self, path):
        # Existing network filesystems may perform implicit authentication even for stat/access.
        absolute = os.path.abspath(path)
        parts = Path(absolute).parts
        for n in range(1, len(parts) + 1):
            prefix = os.path.join(*parts[:n])
            m = mount_for(prefix, self.mounts)
            if m and m.get("remote"):
                return {"path": path, "state": "remote_mount_probe_excluded", "method": "mount_inventory_only"}
            if os.path.islink(prefix):
                return {"path": path, "state": "symlink_probe_excluded", "method": "inventory_only"}
        return path_probe(path)

    def identity(self):
        s = parse_status(self.inventory_text("/proc/self/status"))
        kernel = self.inventory_text("/proc/sys/kernel/osrelease") or ""
        self.wsl = "microsoft" in kernel.lower() or "WSL_INTEROP" in os.environ or "WSL_DISTRO_NAME" in os.environ
        caps = int(s.get("CapEff", "0").strip(), 16) if s else None
        dangerous = {1: "DAC_OVERRIDE", 2: "DAC_READ_SEARCH", 6: "SETGID", 7: "SETUID", 12: "NET_ADMIN", 16: "SYS_MODULE", 19: "SYS_PTRACE", 21: "SYS_ADMIN", 22: "SYS_BOOT", 27: "MKNOD", 39: "BPF"}
        active = [name for bit, name in dangerous.items() if caps is not None and caps & (1 << bit)]
        self.inventory["identity"] = {"uid": os.getuid(), "euid": os.geteuid(), "gid": os.getegid(), "groups": os.getgroups(),
            "wsl_detected": self.wsl, "kernel_release": kernel.strip(), "dangerous_effective_capabilities": active,
            "cap_eff": s.get("CapEff", "").strip(), "cap_permitted": s.get("CapPrm", "").strip(),
            "cap_ambient": s.get("CapAmb", "").strip(), "cap_bounding": s.get("CapBnd", "").strip(),
            "no_new_privs": s.get("NoNewPrivs", "").strip(), "seccomp": s.get("Seccomp", "").strip(),
            "uid_map": self.inventory_text("/proc/self/uid_map"), "gid_map": self.inventory_text("/proc/self/gid_map")}
        if os.geteuid() == 0 or active:
            self.outcome("privileges", "unmet", "Root identity or broad effective capabilities observed; scope is this Linux namespace, not Windows administrator")
            self.finding("privileges", "current Linux context", "privileged authority", "observed", "kernel_inventory", "Broad Linux authority; namespace mapping and host reach need separate evidence", "high")
        elif s and s.get("CapPrm", "0").strip() == "0000000000000000" and s.get("CapAmb", "0").strip() == "0000000000000000":
            self.outcome("privileges", "met", "Non-root, no effective/permitted/ambient capabilities; delegated elevation assessed separately")
        nnp, sec = s.get("NoNewPrivs", "").strip(), s.get("Seccomp", "").strip()
        if nnp == "1" and sec in ("1", "2"):
            self.outcome("kernel_controls", "met", "NoNewPrivs and seccomp present; filter quality not established")
        elif s:
            self.outcome("kernel_controls", "unmet", "NoNewPrivs plus seccomp combination absent")
        ns = {}
        for name in ("user", "pid", "mnt", "net", "ipc", "uts", "cgroup"):
            try:
                own, init = os.readlink("/proc/self/ns/" + name), os.readlink("/proc/1/ns/" + name)
                ns[name] = {"same_as_visible_pid1": own == init}
            except OSError as exc:
                ns[name] = {"error": error_kind(exc)}
        limits = {}
        for name in ("RLIMIT_CPU", "RLIMIT_AS", "RLIMIT_NPROC", "RLIMIT_NOFILE", "RLIMIT_FSIZE"):
            limits[name] = list(resource.getrlimit(getattr(resource, name)))
        self.inventory["containment"] = {"namespaces": ns, "rlimits": limits,
            "cgroup_membership": self.inventory_text("/proc/self/cgroup"),
            "lsm_label": self.inventory_text("/proc/self/attr/current"),
            "ptrace_scope": self.inventory_text("/proc/sys/kernel/yama/ptrace_scope")}
        # Visible PID 1 is not necessarily host PID 1. No positive host isolation inference.

    def files_and_bridges(self):
        text = self.inventory_text("/proc/self/mountinfo", 2 * 1024 * 1024)
        if text is not None:
            try:
                self.mounts = parse_mounts(text)
            except (ValueError, IndexError):
                self.errors.append({"target": "mountinfo", "category": "parse_error"})
        relevant = [dict(m, access=self.probe(m["target"])) for m in self.mounts if m["shared"]]
        self.inventory["shared_mounts"] = relevant
        exposed = [m for m in relevant if m["access"].get("read_permission") or m["access"].get("write_permission")]
        if exposed:
            self.outcome("host_files", "unmet", "Windows, remote or shared mount access observed; permissions are Linux-view analysis, not write operations")
            for m in exposed[:50]:
                self.finding("host_files", m["target"], "shared filesystem access", "permission_indicated", "permission_analysis", "Data reach and potential host/shared-file modification", "high")
        elif text is not None and self.mounts:
            self.outcome("host_files", "unknown", "No recognized accessible bridge; bind mounts, hidden namespaces and manual remount authority cannot be excluded")
        config = self.inventory_text("/etc/wsl.conf", 65536)
        declared = {}
        if config is not None:
            try:
                parser = configparser.ConfigParser(interpolation=None, strict=False)
                parser.read_string(config)
                for section, names in {"interop": ("enabled", "appendWindowsPath"), "automount": ("enabled", "mountFsTab"), "boot": ("systemd",)}.items():
                    for name in names:
                        if parser.has_option(section, name):
                            value = parser.get(section, name).strip().lower()
                            declared[section + "." + name] = value if value in ("true", "false") else "unrecognized"
                declared["boot.command_present"] = parser.has_option("boot", "command")
            except configparser.Error:
                declared["parse_error"] = True
        self.inventory["wsl_declared_configuration"] = declared
        bf = self.inventory_text("/proc/sys/fs/binfmt_misc/WSLInterop", 8192)
        global_bf = self.inventory_text("/proc/sys/fs/binfmt_misc/status", 8192)
        sockets, enumeration_error = [], None
        try:
            for entry in itertools.islice(Path("/run/WSL").iterdir(), 256):
                if entry.name.endswith("_interop"):
                    sockets.append(self.probe(str(entry)))
        except OSError as exc:
            enumeration_error = error_kind(exc)
        interop_env = os.environ.get("WSL_INTEROP")
        if interop_env:
            sockets.append(self.probe(interop_env))
        active_binfmt = bool(bf and bf.splitlines()[0] == "enabled" and global_bf and global_bf.strip() == "enabled")
        usable_sockets = [p for p in sockets if p.get("kind") == "socket" and p.get("write_permission")]
        self.inventory["interop"] = {"binfmt_enabled": active_binfmt, "entry_present": bf is not None,
            "sockets": sockets, "enumeration_error": enumeration_error,
            "windows_path_entries": sum(bool(re.search(r"(?:^/mnt/[a-z]/|/Windows/)", p, re.I)) for p in os.environ.get("PATH", "").split(":")),
            "init_present": path_probe("/init").get("state") == "present"}
        if active_binfmt or usable_sockets:
            self.outcome("interop", "unmet", "Windows launch registration or permission-accessible interop socket observed; launch not exercised")
            self.finding("interop", "/run/WSL and binfmt_misc", "Windows process launch bridge", "available_or_indicated", "inventory_and_permission_analysis", "Potential authority of the launching Windows account; disabling PATH alone is not isolation", "high")
        elif not self.wsl:
            self.outcome("interop", "unknown", "WSL not detected in visible context; an outer WSL environment may be hidden")
        else:
            self.outcome("interop", "unknown", "No active bridge observed; direct /init, hidden servers and re-registration authority unverified")
        gui_paths = ["/mnt/wslg", "/tmp/.X11-unix", "/mnt/wslg/PulseServer"]
        wayland = os.environ.get("WAYLAND_DISPLAY")
        if wayland:
            gui_paths.append(wayland if wayland.startswith("/") else os.path.join(os.environ.get("XDG_RUNTIME_DIR", "/mnt/wslg/runtime-dir"), wayland))
        gui = [self.probe(p) for p in gui_paths]
        self.inventory["gui_bridges"] = {"paths": gui, "display_variables_present": [n for n in ("DISPLAY", "WAYLAND_DISPLAY", "PULSE_SERVER") if os.environ.get(n)]}
        if any(p.get("read_permission") or p.get("write_permission") for p in gui if p.get("state") == "present"):
            self.outcome("gui", "unmet", "GUI/audio bridge paths accessible; clipboard/screen interaction not exercised")
            self.finding("gui", "GUI/audio bridge", "desktop IPC", "permission_indicated", "permission_analysis", "Additional host-facing input/output channels; not proof of arbitrary Windows desktop access")
        controls = [path_probe(p) for p in ("/etc/wsl.conf", "/etc/fstab", "/etc/sudoers", "/etc/sudoers.d", "/etc/systemd/system", "/proc/sys/fs/binfmt_misc/register")]
        self.inventory["control_paths"] = controls
        # Missing files may be creatable through their parent. Parent write implies potential, not proven create.
        for p in controls:
            p["parent_write_permission"] = access(os.path.dirname(p["path"]), os.W_OK | os.X_OK)
        if any(p.get("write_permission") or p.get("parent_write_permission") for p in controls):
            self.outcome("control_integrity", "unmet", "Control file/directory modification or replacement permission indicated")
            self.finding("control_integrity", "Linux boot/restriction configuration", "persistent control changes", "permission_indicated", "permission_analysis", "Potential to weaken Linux/WSL controls or alter privileged bootstrap", "high")
        profiles, profile_error = [], None
        try:
            homes = list(itertools.islice(Path("/home").iterdir(), 64)) + [Path("/root")]
            for home in homes:
                item = self.probe(str(home))
                if item.get("state") == "present" and item.get("uid") != os.geteuid():
                    profiles.append(item)
                    for relative in (".ssh", ".aws/credentials", ".git-credentials", ".config", ".kube/config"):
                        profiles.append(self.probe(str(home / relative)))
        except OSError as exc:
            profile_error = error_kind(exc)
        self.inventory["other_linux_profiles"] = {"paths": profiles, "enumeration_error": profile_error, "limit": 64,
            "method": "permission_analysis_only; no foreign-profile contents read"}
        if any(p.get("read_permission") for p in profiles if p.get("kind") == "file"):
            self.outcome("host_files", "unmet", "Read permission indicated for another Linux user's credential file")
            self.finding("host_files", "foreign Linux profile credential paths", "other-user file read", "permission_indicated", "permission_analysis", "Another Linux identity's credential files may be accessible", "high")

    def processes_and_brokers(self):
        sampled, denied, granted, unresolved = 0, 0, [], 0
        try:
            pids = list(itertools.islice((p for p in Path("/proc").iterdir() if p.name.isdigit()), self.args.max_processes + 1))
            pids.sort(key=lambda p: int(p.name))
        except OSError as exc:
            self.errors.append({"target": "/proc", "category": error_kind(exc)})
            pids = []
            unresolved += 1
        limited = len(pids) > self.args.max_processes
        for p in pids[:self.args.max_processes]:
            try:
                uid = p.stat().st_uid
                if uid == os.geteuid():
                    continue
                sampled += 1
                fd = os.open(str(p / "mem"), os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC)
                os.close(fd)  # NEVER read, attach, write, signal or duplicate a foreign handle.
                granted.append({"pid": int(p.name), "uid": uid})
            except OSError as exc:
                if exc.errno in (errno.EACCES, errno.EPERM):
                    denied += 1
                else:
                    unresolved += 1
        self.inventory["process_memory"] = {"foreign_uid_sampled": sampled, "open_denied": denied, "read_handle_granted": granted,
            "unresolved": unresolved, "enumeration_limited": limited, "same_uid_sessions": "not distinguished; remains unknown"}
        if granted:
            self.outcome("process_memory", "unmet", "Read-only memory handle granted for visible foreign UID; no memory bytes read")
            self.finding("process_memory", granted, "foreign-user memory read handle", "granted", "access_request", "Potential exposure of another identity's process data; sensitive content not inspected", "high")
        elif sampled and not limited and not unresolved:
            self.outcome("process_memory", "met", "Read opens denied for sampled visible foreign-user processes; same-UID human sessions and hidden processes excluded")
        inherited = {"count": 0, "writable_regular_files": 0, "socket_count": 0, "errors": 0, "limit": 256, "limited": False}
        try:
            for index, p in enumerate(itertools.islice(Path("/proc/self/fd").iterdir(), 257)):
                if index == 256:
                    inherited["limited"] = True
                    break
                if int(p.name) <= 2:
                    continue
                try:
                    s = p.stat()
                    flags = self.inventory_text("/proc/self/fdinfo/" + p.name, 8192) or ""
                    match = re.search(r"^flags:\s*([0-7]+)", flags, re.M)
                    inherited["count"] += 1
                    inherited["socket_count"] += int(stat.S_ISSOCK(s.st_mode))
                    inherited["writable_regular_files"] += int(stat.S_ISREG(s.st_mode) and bool(match) and (int(match[1], 8) & os.O_ACCMODE) in (os.O_WRONLY, os.O_RDWR))
                except OSError:
                    inherited["errors"] += 1
        except OSError:
            inherited["errors"] += 1
        self.inventory["inherited_fds"] = inherited
        paths = ["/run/docker.sock", "/var/run/docker.sock", "/run/podman/podman.sock", "/run/containerd/containerd.sock", "/run/libvirt/libvirt-sock",
                 "/mnt/wsl/docker-desktop/shared-sockets/guest-services/docker.sock", "/run/user/%s/podman/podman.sock" % os.geteuid()]
        if os.environ.get("SSH_AUTH_SOCK"):
            paths.append(os.environ["SSH_AUTH_SOCK"])
        brokers = [self.probe(p) for p in paths]
        self.inventory["broker_paths"] = brokers
        self.inventory["delegation_signals"] = {"variables_present": [n for n in ("SSH_AUTH_SOCK", "GIT_ASKPASS", "SSH_ASKPASS", "DOCKER_HOST", "KUBECONFIG", "AWS_PROFILE", "AZURE_CONFIG_DIR", "GOOGLE_APPLICATION_CREDENTIALS", "WSLENV") if os.environ.get(n)],
            "sudo_and_credential_helpers": "not executed; cached/delegated rights unknown"}
        self.inventory["devices"] = [path_probe(p) for p in ("/dev/dxg", "/dev/vsock", "/dev/kvm", "/dev/fuse", "/dev/net/tun", "/dev/mem")]
        if any(p.get("kind") == "socket" and p.get("write_permission") for p in brokers):
            self.outcome("delegation", "unmet", "Permission-accessible container/virtualization/SSH broker socket; API authorization unverified")
            self.finding("delegation", "broker sockets", "delegated execution or signing", "permission_indicated", "permission_analysis", "Potential infrastructure or credential authority; socket permissions do not prove daemon/API privilege", "high")
        # Never run sudo or helpers: credential caches, sudo rules, keyrings and brokers stay unknown.

    def secrets(self):
        env_hits = []
        for name, value in os.environ.items():
            categories = self.detect(value)
            if value and (SECRET_ENV.search(name) or categories):
                env_hits.append({"category": "secret_named_variable" if SECRET_ENV.search(name) else "token_pattern", "suspected_types": categories})
                if len(value) >= 4:
                    self.redactions.add(value)
        home = str(Path.home())
        roots = self.args.scan_root or [self.args.workspace, home + "/.ssh", home + "/.aws", home + "/.azure", home + "/.kube", home + "/.config/gcloud", home + "/.config/gh"]
        known = [home + "/" + p for p in (".git-credentials", ".netrc", ".npmrc", ".pypirc", ".claude.json", ".codex/auth.json", ".docker/config.json")]
        hits, scan = self.scan(roots, known) if not self.args.no_content_scan else ([], {"disabled": True})
        self.inventory["secrets"] = {"environment_candidates": env_hits, "content_candidates": hits, "scan": scan,
            "known_credential_paths": [self.probe(p) for p in known], "protected_stores_and_remote_scopes": "not tested"}
        if env_hits or hits:
            self.outcome("secrets", "unmet", "Suspected credential material accessible; validity and remote scope not tested")
            self.finding("secrets", "environment and bounded content scan", "credential exposure", "suspected_material_accessible", "bounded_content_detection", "Potential remote access or exfiltration authority; no credentials used", "high")
        # Zero matches never proves no secrets: encrypted stores, formats, exclusions and hidden roots remain.

    def detect(self, text):
        categories = []
        for name, pattern in TOKEN_PATTERNS.items():
            matches = list(pattern.finditer(text))
            if matches:
                categories.append(name)
                for m in matches:
                    value = m[1] if name == "secret_assignment" else m[0]
                    if len(value) >= 4:
                        self.redactions.add(value)
        return categories

    def scan(self, roots, files):
        stats = {"candidate_files": 0, "files_read": 0, "bytes_read": 0, "errors": 0, "skipped_links": 0,
                 "skipped_remote_or_shared": 0, "skipped_oversize_or_binary": 0, "limits_reached": [],
                 "roots": [], "max_files": self.args.max_files, "max_file_bytes": self.args.max_file_bytes,
                 "max_total_bytes": self.args.max_total_bytes, "seconds_budget": self.args.scan_seconds,
                 "budget_kind": "cooperative; local filesystem calls can still block"}
        hits = []
        start = time.monotonic()
        seen = set()
        def candidate(path, root):
            if time.monotonic() - start >= self.args.scan_seconds:
                stats["limits_reached"].append("time")
                return False
            if stats["candidate_files"] >= self.args.max_files or stats["bytes_read"] >= self.args.max_total_bytes:
                stats["limits_reached"].append("file_or_total_byte_budget")
                return False
            if path in seen:
                return True
            seen.add(path)
            stats["candidate_files"] += 1
            m = mount_for(path, self.mounts)
            if not self.mounts or (m and (m["shared"] or m["fs"] in REMOTE_FS)):
                stats["skipped_remote_or_shared"] += 1
                return True
            fd = None
            try:
                if os.path.islink(path):
                    stats["skipped_links"] += 1
                    return True
                fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
                s = os.fstat(fd)
                actual = os.readlink("/proc/self/fd/%s" % fd)
                actual_mount = mount_for(actual, self.mounts)
                if not beneath(actual, root) or not actual_mount or actual_mount["shared"] or actual_mount["fs"] in REMOTE_FS:
                    stats["skipped_remote_or_shared"] += 1
                    return True
                if not stat.S_ISREG(s.st_mode) or s.st_size > self.args.max_file_bytes:
                    stats["skipped_oversize_or_binary"] += 1
                    return True
                remaining = self.args.max_total_bytes - stats["bytes_read"]
                if s.st_size > remaining:
                    stats["limits_reached"].append("total_byte_budget")
                    return False
                data = os.read(fd, min(self.args.max_file_bytes, remaining))
                stats["bytes_read"] += len(data)
                stats["files_read"] += 1
                if data.startswith((b"\xff\xfe", b"\xfe\xff")):
                    text = data.decode("utf-16", errors="replace")
                elif b"\0" in data:
                    stats["skipped_oversize_or_binary"] += 1
                    return True
                else:
                    text = data.decode("utf-8-sig", errors="replace")
                types = self.detect(text)
                if types:
                    hits.append({"path": path, "suspected_types": types, "confidence": "heuristic", "accessibility": "content_read"})
            except OSError:
                stats["errors"] += 1
            finally:
                if fd is not None:
                    os.close(fd)
            return True
        for raw in files + roots:
            root = os.path.abspath(os.path.expanduser(raw))
            stats["roots"].append(root)
            m = mount_for(root, self.mounts)
            if not self.mounts or (m and (m["shared"] or m["fs"] in REMOTE_FS)):
                stats["skipped_remote_or_shared"] += 1
                continue
            if self.probe(root).get("state") in ("remote_mount_probe_excluded", "symlink_probe_excluded"):
                stats["skipped_links"] += 1
                continue
            if os.path.islink(root) or os.path.realpath(root) != root:
                stats["skipped_links"] += 1
                continue
            if os.path.isfile(root):
                if not candidate(root, os.path.dirname(root)):
                    break
                continue
            if not os.path.exists(root):
                continue
            def walk_error(_):
                stats["errors"] += 1
            stop = False
            visited_dirs = 0
            for directory, dirs, names in os.walk(root, followlinks=False, onerror=walk_error):
                visited_dirs += 1
                if visited_dirs > self.args.max_files or time.monotonic() - start >= self.args.scan_seconds:
                    stats["limits_reached"].append("directory_or_time_budget")
                    stop = True
                    break
                dirs[:] = [d for d in dirs if d not in (".git", "node_modules", ".venv", "venv", "__pycache__") and not os.path.islink(os.path.join(directory, d))
                           and not (mount_for(os.path.join(directory, d), self.mounts) or {}).get("shared", False)]
                for name in names:
                    if name in KNOWN_NAMES or name.startswith(".env") or Path(name).suffix.lower() in TEXT_EXT:
                        if not candidate(os.path.join(directory, name), root):
                            stop = True
                            break
                if stop:
                    break
            if stop:
                break
        stats["limits_reached"] = sorted(set(stats["limits_reached"]))
        return hits, stats

    def network(self):
        routes = self.inventory_text("/proc/net/route")
        route_inventory = []
        if routes:
            for line in routes.splitlines()[1:65]:
                cols = line.split()
                try:
                    route_inventory.append({"interface": cols[0], "destination": str(ipaddress.IPv4Address(bytes.fromhex(cols[1])[::-1])),
                        "gateway": str(ipaddress.IPv4Address(bytes.fromhex(cols[2])[::-1])),
                        "mask": str(ipaddress.IPv4Address(bytes.fromhex(cols[7])[::-1]))})
                except (IndexError, ValueError):
                    self.errors.append({"target": "route", "category": "parse_error"})
        resolv = self.inventory_text("/etc/resolv.conf", 65536)
        # resolv.conf is often a symlink: do not bypass safe inventory read rejection.
        ns = []
        if resolv:
            for line in resolv.splitlines():
                if line.startswith("nameserver "):
                    try:
                        ns.append(str(ipaddress.ip_address(line.split()[1])))
                    except ValueError:
                        pass
        listeners = {}
        for name in ("tcp", "tcp6", "udp", "udp6"):
            data = self.inventory_text("/proc/net/" + name)
            listeners[name] = {"entries": max(0, len(data.splitlines()) - 1) if data is not None else None,
                               "scope": "current network namespace; entries include connections"}
        results = []
        for target in self.args.tcp_target:
            host, port = parse_target(target)
            results.append(tcp_probe(host, port, self.args.probe_seconds))
        self.inventory["network"] = {"route_rows": max(0, len(routes.splitlines()) - 1) if routes else None, "ipv4_routes": route_inventory,
            "nameservers": ns, "proxy_variables_present": [n for n in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "all_proxy", "no_proxy") if os.environ.get(n)],
            "socket_tables": listeners, "tcp_probes": results,
            "not_verified": ["DNS/UDP/IPv6 egress policy", "proxy enforcement", "Windows firewall/Hyper-V policy", "NAT/mirrored mode", "host localhost routes", "domain shares and service authorization"]}
        if any(p["result"] == "connected" for p in results):
            self.outcome("network", "unmet", "At least one operator-selected TCP destination reachable; no application payload or credentials sent")
            self.finding("network", [p["target"] for p in results if p["result"] == "connected"], "TCP reach", "connected", "non_destructive_connect", "Observed route can carry data; protocol and remote authority not tested", "high")
        # Refused, timeout, DNS failure, and even a denied target do not prove a general policy.

    def monitoring(self):
        self.inventory["monitoring"] = {"paths": [path_probe(p) for p in ("/var/log/audit", "/var/log/journal", "/run/log/journal")],
            "coverage": "not established", "external_collection": "not visible from inside",
            "tool_channels": "MCP/browser/other harness tools require separate assessment"}
        if any(p.get("write_permission") for p in self.inventory["monitoring"]["paths"]):
            self.outcome("log_integrity", "unmet", "Local log directory write permission indicated; no log changed")
            self.finding("log_integrity", "local log directories", "log modification", "permission_indicated", "permission_analysis", "Potential log alteration; remote copies and immutable flags not verified")

    def sanitize(self, item):
        if isinstance(item, dict):
            return {self.sanitize(k): self.sanitize(v) for k, v in item.items()}
        if isinstance(item, list):
            return [self.sanitize(v) for v in item]
        if not isinstance(item, str):
            return item
        for secret in sorted(self.redactions, key=len, reverse=True):
            item = item.replace(secret, "[REDACTED]")
        for pattern in TOKEN_PATTERNS.values():
            item = pattern.sub("[REDACTED]", item)
        item = re.sub(r"(?i)([a-z][a-z0-9+.-]*://)[^\s/]*@", r"\1[REDACTED]@", item)
        item = re.sub(r"(?i)([a-z][a-z0-9+.-]*://[^\s?#]+)[?#][^\s]*", r"\1[REDACTED]", item)
        return "".join(c if c >= " " and c != "\x7f" else " " for c in item)

    def run(self):
        for method_name in ("identity", "files_and_bridges", "processes_and_brokers", "secrets", "network", "monitoring"):
            try:
                getattr(self, method_name)()
            except Exception as exc:
                # Do not expose exception strings, which can include untrusted secrets or config content.
                self.errors.append({"check": method_name, "category": type(exc).__name__})
        remediation = {"privileges": "Use a non-root agent identity without broad capabilities; assess delegated sudo authority separately.",
            "host_files": "Remove host/shared mounts or expose only a narrowly scoped read-only workspace; use a separate Windows identity.",
            "interop": "Disable interop and Windows PATH import, remove accessible interop servers, and prevent re-enabling bridges; configuration alone is insufficient.",
            "gui": "Remove WSLg/X11/Wayland/audio sockets and related inherited channels if the agent does not need them.",
            "delegation": "Remove container, virtualization and SSH-agent sockets; assess each broker's effective authorization.",
            "secrets": "Keep agent credentials narrowly scoped and short-lived; remove unrelated environment and readable credential files.",
            "network": "Enforce egress outside the agent context, including IPv6, DNS, direct and proxy paths; separately validate host loopback access.",
            "control_integrity": "Make launcher/bootstrap and restriction controls inaccessible for agent modification or replacement.",
            "process_memory": "Separate human and agent identities and process namespaces; enforce and validate ptrace restrictions.",
            "log_integrity": "Collect attributed logs outside agent control and validate tamper resistance and delivery."}
        report = {"schema_version": "1", "checker_version": VERSION, "profile_version": PROFILE,
            "timestamp_utc": datetime.now(timezone.utc).isoformat(), "execution_status": "completed_with_collection_errors" if self.errors else "completed",
            "scope": {"inside_agent_context_only": True, "workspace": self.args.workspace, "windows_execution": False,
                      "non_shell_agent_channels_assessed": False, "independent_attestation": False},
            "assessment": score(self.criteria), "criteria": self.criteria, "findings": self.findings,
            "inventory": self.inventory, "collection_errors": self.errors,
            "recommendations": [remediation[k] for k in dict.fromkeys(f["check_id"] for f in self.findings) if k in remediation],
            "limitations": ["No proof of Windows host isolation or Windows account privilege", "No writes, process memory reads, elevation, discovered executable execution or credential use",
                            "File/IPC write results are permission analysis, not damaging operations", "No matches is not absence of secrets; content on shared/remote/Windows mounts excluded",
                            "Inside-only monitoring, lifecycle, privileged consumers and tool channels remain unverified", "Scores are checklist indices, not safety probabilities; compare matching profiles and scopes"]}
        return self.sanitize(report)


def parse_target(value):
    # Numeric IP only: no uncontrolled DNS lookup or resolver side effects.
    if value.startswith("["):
        host, sep, port = value[1:].partition("]:")
    else:
        host, sep, port = value.rpartition(":")
    if not sep:
        raise ValueError("Use numeric IPv4:port or [IPv6]:port")
    ipaddress.ip_address(host)
    number = int(port)
    if not 1 <= number <= 65535:
        raise ValueError("Invalid port")
    return host, number


def tcp_worker(host, port, seconds, connection):
    sock = None
    try:
        family = socket.AF_INET6 if ":" in host else socket.AF_INET
        sock = socket.socket(family, socket.SOCK_STREAM)
        sock.settimeout(seconds)
        sock.connect((host, port))
        connection.send("connected")
    except OSError as exc:
        connection.send(error_kind(exc))
    finally:
        if sock:
            sock.close()
        connection.close()


def tcp_probe(host, port, seconds):
    ctx = multiprocessing.get_context("spawn")
    parent, child = ctx.Pipe(duplex=False)
    p = ctx.Process(target=tcp_worker, args=(host, port, seconds, child))
    result = "unknown"
    try:
        p.start()
        child.close()
        if parent.poll(seconds + 1):
            try:
                result = parent.recv()
            except EOFError:
                result = "worker_failed"
        else:
            result = "timeout"
    finally:
        if p.pid:
            if p.is_alive():
                p.terminate()  # Only our own isolated probe worker.
            p.join(1)
            if p.is_alive():
                p.kill()
                p.join(1)
        parent.close()
        child.close()
    return {"target": ("[%s]:%s" if ":" in host else "%s:%s") % (host, port), "result": result,
            "method": "tcp_connect_no_payload", "policy_denial_proven": False}


def compare_policy(report, policy):
    if not isinstance(policy, dict) or set(policy) - {"profile_version", "require_met", "minimum_lower_score"}:
        raise ValueError("Unsupported policy fields")
    if policy.get("profile_version", PROFILE) != PROFILE:
        raise ValueError("Policy profile mismatch")
    required = policy.get("require_met", [])
    if not isinstance(required, list) or any(k not in REGISTRY for k in required):
        raise ValueError("Unknown policy criterion")
    minimum = policy.get("minimum_lower_score")
    if minimum is not None and (type(minimum) is not int or not 0 <= minimum <= 100):
        raise ValueError("Invalid minimum score")
    rows = [{"criterion": k, "result": "compliant" if report["criteria"][k]["outcome"] == "met" else "violation" if report["criteria"][k]["outcome"] == "unmet" else "unknown"} for k in required]
    if minimum is not None:
        a = report["assessment"]
        rows.append({"criterion": "minimum_lower_score", "result": "compliant" if a["lower"] >= minimum else "violation" if a["upper"] < minimum else "unknown"})
    return {"status": "violation" if any(r["result"] == "violation" for r in rows) else "unknown" if not rows or any(r["result"] == "unknown" for r in rows) else "compliant", "checks": rows}


def positive_int(value):
    n = int(value)
    if n <= 0:
        raise argparse.ArgumentTypeError("Must be positive")
    return n


def arguments():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--json", action="store_true", help="One JSON object on stdout")
    p.add_argument("--workspace", default=os.getcwd())
    p.add_argument("--scan-root", action="append", default=[], help="Replace default directory scan roots; repeatable. Known credential files still checked")
    p.add_argument("--no-content-scan", action="store_true")
    p.add_argument("--tcp-target", action="append", default=[], help="Operator-approved numeric IP:port or [IPv6]:port; no payload, credentials or DNS")
    p.add_argument("--probe-seconds", type=positive_int, default=3)
    p.add_argument("--max-processes", type=positive_int, default=128)
    p.add_argument("--max-files", type=positive_int, default=5000)
    p.add_argument("--max-file-bytes", type=positive_int, default=1048576)
    p.add_argument("--max-total-bytes", type=positive_int, default=33554432)
    p.add_argument("--scan-seconds", type=positive_int, default=30)
    p.add_argument("--policy", help="Local JSON policy; no executable configuration")
    p.add_argument("--fail-on-policy", action="store_true", help="Exit 3 for policy violation or unknown")
    a = p.parse_args()
    if a.fail_on_policy and not a.policy:
        p.error("--fail-on-policy requires --policy")
    if len(a.tcp_target) > 16:
        p.error("At most 16 TCP targets")
    try:
        for t in a.tcp_target:
            parse_target(t)
    except ValueError:
        p.error("Targets must be numeric IPv4:port or [IPv6]:port")
    a.workspace = os.path.abspath(a.workspace)
    return a


def human(report):
    a = report["assessment"]
    lines = ["WSL/Linux agent sandbox exposure assessment", "%s | score %s-%s/100 | coverage %s%%" % (a["verdict"], a["lower"], a["upper"], a["coverage_percent"])]
    for dim, d in a["dimensions"].items():
        lines.append("  %s: %s-%s/25, coverage %s%%" % (dim, d["lower"], d["upper"], d["coverage_percent"]))
    lines.append("Observed exposures:")
    findings = sorted(report["findings"], key=lambda f: 0 if f["severity"] == "high" else 1)
    lines.extend("  [%s] %s: %s" % (f["severity"], f["check_id"], f["impact"]) for f in findings[:5])
    if not findings:
        lines.append("  No exposure established; this is not proof of isolation.")
    lines.append("Essential unknowns: " + ", ".join(a["essential_unknowns"]))
    if "policy" in report:
        lines.append("Policy: " + report["policy"]["status"])
    lines.append("Use --json for all evidence, scope, exclusions and collection errors.")
    return "\n".join(lines)


def main():
    args = arguments()
    if sys.platform != "linux":
        print('{"execution_status":"failed","error":"Linux required"}' if args.json else "Linux required", file=sys.stdout)
        return 1
    policy = None
    if args.policy:
        try:
            text, err = read_small(args.policy, 65536)
            if err:
                raise ValueError("Policy unreadable")
            policy = json.loads(text)
            compare_policy({"criteria": {k: {"outcome": "unknown"} for k in REGISTRY}, "assessment": {"lower": 0, "upper": 100}}, policy)
        except (ValueError, TypeError):
            print('{"execution_status":"failed","error":"Invalid or unreadable policy"}' if args.json else "Invalid or unreadable policy")
            return 1
    report = Checker(args).run()
    if policy is not None:
        report["policy"] = compare_policy(report, policy)
    print(json.dumps(report, indent=2, ensure_ascii=True) if args.json else human(report))
    return 3 if args.fail_on_policy and report["policy"]["status"] != "compliant" else 0


if __name__ == "__main__":
    sys.exit(main())
