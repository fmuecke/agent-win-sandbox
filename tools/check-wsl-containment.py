#!/usr/bin/env python3
"""Small, native WSL exposure checker (Python 3 standard library only).

Run INSIDE the exact agent shell, as its normal user, without sudo:
  python3 check-wsl-containment.py
  python3 check-wsl-containment.py --probe-interop
  python3 check-wsl-containment.py --canary /mnt/c/AgentCanary.txt
  python3 check-wsl-containment.py --tcp 172.20.0.1:8080 --tcp '[::1]:8080'
  python3 check-wsl-containment.py --json > wsl-report.json

Default: inventory, permission checks and `sudo -n -l` (no elevated command).
Opt-in: harmless Windows cmd /c exit 0, existing regular-file canaries,
and TCP handshakes to specified literal IP addresses. No port scanning,
secret contents, mount attempts, firewall changes, or hardening changes.
Canary checks open files without reading/writing/truncating; symlinks rejected.
TCP probes transmit no application payload. Sudo/connection probes may be logged.

Severity describes exposure, not a confirmed exploit. No aggregate security
score: missing/blocked evidence is not proof of isolation. Exit 0 = completed,
2 = unsupported environment. Reports can contain private filesystem paths.

Hardening baseline (merge into /etc/wsl.conf; do not overwrite other sections):
  [automount]
  enabled=false
  mountFsTab=false
  [interop]
  enabled=false
  appendWindowsPath=false
Then restart WSL from Windows; `wsl --shutdown` stops ALL running distros.
For CLI-only WSL, consider guiApplications=false in [wsl2] of .wslconfig.
These settings reduce bridges, but Linux root/privileges or Windows interop
may allow bypass. Automount=false does NOT forbid manual mounting.
Keep the agent unprivileged, restrict Windows identity/ACLs, and enforce
network restrictions outside the agent's control. Host-side policies cannot
be verified conclusively from this script. A separate distro is not itself
an independent VM security boundary. Review shared code before host execution.

References:
https://learn.microsoft.com/windows/wsl/wsl-config
https://learn.microsoft.com/windows/wsl/networking
https://wsl.dev/technical-documentation/interop/
"""
import argparse
import configparser
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import socket
import stat
import struct
import subprocess

LIMIT = 256 * 1024


def read(path):
    try:
        with open(path, encoding='utf-8', errors='replace') as f:
            return f.read(LIMIT)
    except OSError:
        return None


def unescape_mount(value):
    return re.sub(r'\\([0-7]{3})', lambda m: chr(int(m[1], 8)), value)


def mounts_from(text):
    result = []
    for line in (text or '').splitlines():
        fields = line.split()
        if len(fields) >= 4:
            source, target, kind, options = fields[:4]
            result.append((unescape_mount(source), unescape_mount(target), kind, options))
    return result


def host_mount(m):
    source, target, kind, options = m
    return (kind == 'drvfs' or (kind == '9p' and 'aname=drvfs' in options)
            or bool(re.match(r'^[A-Za-z]:', source)))


def tcp_target(value):
    try:
        host, port = value.rsplit(':', 1)
        host = str(ipaddress.ip_address(host.strip('[]')))
        port = int(port)
        if not 1 <= port <= 65535:
            raise ValueError()
        return host, port
    except ValueError:
        raise argparse.ArgumentTypeError('Use literal IP:PORT or [IPv6]:PORT')


def canary_access(path, mode):
    fd = None
    try:
        if not stat.S_ISREG(os.lstat(path).st_mode):
            return 'not-regular-or-symlink'
        fd = os.open(path, mode | os.O_NONBLOCK | os.O_NOFOLLOW)
        return 'allowed' if stat.S_ISREG(os.fstat(fd).st_mode) else 'not-regular'
    except PermissionError:
        return 'denied'
    except FileNotFoundError:
        return 'missing'
    except OSError:
        return 'error-or-symlink'
    finally:
        if fd is not None:
            os.close(fd)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--json', action='store_true', help='Machine-readable report on stdout')
    parser.add_argument('--probe-interop', action='store_true', help='Try harmless Windows cmd /c exit 0')
    parser.add_argument('--canary', action='append', default=[], metavar='FILE', help='Existing regular file, repeated as needed')
    parser.add_argument('--tcp', action='append', default=[], type=tcp_target, metavar='IP:PORT', help='Explicit endpoint; TCP handshake only, 2 second timeout')
    args = parser.parse_args()
    kernel = read('/proc/sys/kernel/osrelease') or ''
    if 'microsoft' not in kernel.lower() and 'wsl' not in kernel.lower():
        print('Not a detected WSL environment; run inside your WSL agent shell.')
        return 2
    findings = []

    def add(level, check, evidence, hint=''):
        findings.append(dict(level=level, check=check, evidence=evidence, hint=hint))

    add('INFO', 'Context', f'uid={os.geteuid()}; kernel={kernel.strip()}', 'Results apply only to this process identity and namespaces.')
    if 'wsl2' not in kernel.lower() and 'microsoft-standard' not in kernel.lower():
        add('WARN', 'WSL version', 'Kernel does not clearly identify WSL 2.', 'Confirm with wsl --list --verbose on Windows; prefer WSL 2.')
    if os.geteuid() == 0:
        add('HIGH', 'Linux root', 'Agent context is root.', 'Use a dedicated Linux user without sudo. Linux root does not imply Windows administrator, but can undo Linux restrictions.')
    if shutil.which('sudo'):
        try:
            r = subprocess.run(['sudo', '-n', '-l'], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=3)
            if r.returncode == 0:
                add('WARN', 'Sudo policy', 'Sudo policy can be listed without prompting; command details suppressed.', 'Review allowed commands and cached authentication outside this checker. Listing success alone does not prove unrestricted root access.')
            else:
                add('UNKNOWN', 'Sudo policy', 'Noninteractive policy query failed.', 'This does not prove absence of sudo rights; check policy as the administrator.')
        except (OSError, subprocess.TimeoutExpired):
            add('UNKNOWN', 'Sudo policy', 'Query unavailable or timed out.')
    status = read('/proc/self/status') or ''
    cap = re.search(r'^CapEff:\s*([0-9a-fA-F]+)', status, re.M)
    if cap:
        mask = int(cap[1], 16)
        names = [name for bit, name in [(1, 'DAC_OVERRIDE'), (2, 'DAC_READ_SEARCH'), (19, 'SYS_PTRACE'), (21, 'SYS_ADMIN')] if mask & (1 << bit)]
        if names:
            add('HIGH', 'Effective capabilities', ', '.join(names), 'Drop these capabilities; SYS_ADMIN can permit mounts, subject to other restrictions.')

    conf = configparser.ConfigParser(interpolation=None, strict=False)
    raw = read('/etc/wsl.conf')
    try:
        conf.read_string(raw or '')
        for section, key in [('automount', 'enabled'), ('automount', 'mountfstab'), ('interop', 'enabled'), ('interop', 'appendwindowspath')]:
            try:
                enabled = conf.getboolean(section, key, fallback=True)
                add('WARN' if enabled else 'INFO', f'Config {section}.{key}', 'Enabled/default' if enabled else 'Disabled in configuration', 'Set false if unnecessary; configuration is not proof of current runtime enforcement.')
            except ValueError:
                add('UNKNOWN', f'Config {section}.{key}', 'Invalid boolean setting.')
    except configparser.Error:
        add('UNKNOWN', 'WSL config', 'Configuration could not be parsed.')
    if raw is None and Path('/etc/wsl.conf').exists():
        add('UNKNOWN', 'WSL config', 'Configuration unreadable; defaults above are assumptions.')
    for path in ['/etc/wsl.conf', '/etc/fstab', '/proc/sys/fs/binfmt_misc/WSLInterop']:
        if os.access(path, os.W_OK) or (not Path(path).exists() and os.access(str(Path(path).parent), os.W_OK)):
            add('HIGH', 'Writable bridge control', path, 'Protect bridge configuration and runtime controls from the agent; avoid root/sudo.')

    raw_mounts = read('/proc/mounts')
    mounts = mounts_from(raw_mounts)
    if raw_mounts is None:
        add('UNKNOWN', 'Mount inventory', '/proc/mounts unreadable.')
    windows = [m for m in mounts if host_mount(m)]
    for source, target, kind, options in windows[:40]:
        mode = 'rw' if 'rw' in options.split(',') else 'ro'
        add('HIGH' if mode == 'rw' else 'WARN', 'Windows filesystem mount', f'{target} ({kind}, {mode}); directory read/search={os.access(target, os.R_OK | os.X_OK)}', 'Remove unnecessary mounts; restrict Windows ACLs. A rw mount does not prove write access to every file. Use --canary for effective file access.')
    if not windows and raw_mounts is not None:
        add('INFO', 'Windows filesystem mounts', 'No recognized DrvFs/Windows drive mounts visible.', 'Manual mounts and indirect bridges remain untested.')
    if len(windows) > 40:
        add('UNKNOWN', 'Mount inventory limit', 'Additional Windows mounts omitted.')
    if re.search(r'drvfs|[A-Za-z]:[\\/]', read('/etc/fstab') or '', re.I):
        add('WARN', 'fstab bridge', 'Windows mount references present; contents suppressed.', 'Review /etc/fstab; disable mountFsTab or remove unnecessary entries.')
    interop = read('/proc/sys/fs/binfmt_misc/WSLInterop')
    if interop and interop.startswith('enabled'):
        add('HIGH', 'Runtime Windows interop', 'WSLInterop binfmt handler enabled.', 'Disable interop and restart WSL; verify from the agent context. Availability is not yet an execution probe.')
    else:
        add('UNKNOWN', 'Runtime Windows interop', 'Enabled binfmt handler not observed.', 'A missing/disabled handler alone does not prove every bridge is blocked.')
    for variable in ['WSL_INTEROP', 'WSLENV', 'SSH_AUTH_SOCK', 'DISPLAY', 'WAYLAND_DISPLAY', 'PULSE_SERVER', 'DOCKER_HOST']:
        if os.environ.get(variable):
            add('WARN', 'Bridge environment', f'{variable} is set; value suppressed.', 'Review forwarded credentials, sockets, GUI/audio and service connections; remove unnecessary forwarding.')
    if any(re.search(r'(^|/)(mnt/[a-z]/|windows/)', p, re.I) for p in os.environ.get('PATH', '').split(':')):
        add('WARN', 'Windows PATH', 'Likely Windows paths in PATH.', 'Set appendWindowsPath=false. PATH removal alone does not block Windows execution.')

    if args.probe_interop:
        candidates = [shutil.which('cmd.exe')]
        candidates += [str(Path(m[1]) / 'Windows/System32/cmd.exe') for m in windows]
        exe = next((x for x in candidates if x and Path(x).is_file()), None)
        if not exe:
            add('UNKNOWN', 'Interop execution probe', 'No cmd.exe located; not tested.')
        else:
            try:
                r = subprocess.run([exe, '/d', '/c', 'exit', '0'], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=3)
                add('HIGH' if r.returncode == 0 else 'UNKNOWN', 'Interop execution probe', 'Windows command executed successfully.' if r.returncode == 0 else 'Command returned nonzero; reason unknown.', 'Successful interop exposes the owning Windows identity. Disable it or use a restricted Windows account.')
            except (OSError, subprocess.TimeoutExpired):
                add('UNKNOWN', 'Interop execution probe', 'Command failed or timed out; not proof of containment.')

    unix = read('/proc/net/unix')
    socket_paths = set()
    for line in (unix or '').splitlines()[1:]:
        fields = line.split(maxsplit=7)
        if len(fields) == 8 and re.search(r'docker|podman|ssh|agent|interop|wayland|pulse|/mnt/wsl', fields[7], re.I):
            socket_paths.add(fields[7])
    for p in sorted(socket_paths)[:40]:
        abstract = p.startswith('@')
        add('WARN', 'Potential bridge socket', f'{p}; filesystem write permission={"unknown (abstract)" if abstract else os.access(p, os.W_OK)}', 'Permission is not an authenticated connection test. Remove unnecessary sockets from the agent namespace; Docker access may grant control of its backend.')
    if unix is None or len(socket_paths) > 40:
        add('UNKNOWN', 'Socket inventory', 'Unavailable or truncated.')
    for p in ['/mnt/wslg', '/mnt/wsl', '/dev/dxg']:
        if Path(p).exists():
            add('WARN', 'Shared integration surface', p, 'Inspect exposed resources. For CLI-only use disable WSLg with guiApplications=false; remove unneeded shared mounts/devices from the agent namespace.')

    routes = read('/proc/net/route')
    for line in (routes or '').splitlines()[1:]:
        f = line.split()
        if len(f) >= 4 and f[1] == '00000000':
            try:
                gateway = socket.inet_ntoa(struct.pack('<I', int(f[2], 16)))
                add('INFO', 'Default gateway candidate', gateway, 'In NAT mode this may be the Windows host; mirrored mode differs. Test only explicit host endpoints with --tcp.')
            except ValueError:
                pass
    resolvers = re.findall(r'^nameserver\s+(\S+)', read('/etc/resolv.conf') or '', re.M)
    add('INFO', 'DNS configuration', f'{len(resolvers)} resolver entries; no DNS query performed.', 'DNS tunneling/resolver addresses do not prove host location or exfiltration protection. Enforce DNS and egress policy outside the agent.')
    add('UNKNOWN', 'Network containment', 'Host firewall, networking mode and DNS/UDP egress not verified.', 'Validate Windows/Hyper-V Firewall and proxy allowlists externally. Proxy environment variables are not enforcement. A failed TCP probe proves only that attempt failed.')
    for host, port in args.tcp:
        family = socket.AF_INET6 if ':' in host else socket.AF_INET
        try:
            with socket.socket(family, socket.SOCK_STREAM) as s:
                s.settimeout(2)
                s.connect((host, port))
            add('WARN', 'TCP endpoint probe', f'{host}:{port}: connected', 'Classify this endpoint and remove unintended host/service reach; no application request was sent.')
        except OSError:
            add('UNKNOWN', 'TCP endpoint probe', f'{host}:{port}: connection failed', 'Failure may mean no listener, routing failure or filtering; not proof of firewall enforcement.')
    for p in args.canary:
        results = {name: canary_access(p, mode) for name, mode in [('read', os.O_RDONLY), ('write', os.O_WRONLY)]}
        add('HIGH' if 'allowed' in results.values() else 'UNKNOWN', 'Canary file access', f'{p}: {results}', 'Canary contents unchanged. If this access is unintended, restrict host ACLs/mounts; no inference about other files.')

    counts = {level: sum(f['level'] == level for f in findings) for level in ['HIGH', 'WARN', 'UNKNOWN', 'INFO']}
    report = dict(schema_version=1, summary=counts, findings=findings, limitation='Exposure inventory, not isolation certification. No secret content scanned. Missing evidence remains unknown.')
    if args.json:
        print(json.dumps(report, indent=2, ensure_ascii=True))
    else:
        print('WSL containment: ' + ', '.join(f'{n} {level}' for level, n in counts.items()))
        for f in findings:
            # Escape control characters in potentially untrusted paths/evidence.
            safe = lambda v: json.dumps(v, ensure_ascii=True)[1:-1]
            print(f"\n[{f['level']}] {f['check']}: {safe(f['evidence'])}")
            if f['hint']:
                print('  Hint: ' + safe(f['hint']))
        print('\n' + report['limitation'])
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
