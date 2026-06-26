# Container/VM Isolation Probe Specification

A structured probe for assessing container and VM isolation boundaries. Designed to run inside a target environment (Docker container, Kubernetes pod, Firecracker microVM, EC2 instance, ECS task, Lambda, etc.) and report what's visible, reachable, and exploitable.

Future goal: an agent-callable tool that can be deployed into arbitrary targets and returns a structured isolation assessment.

## Architecture

```
probe agent
    |
    +--> deploys probe.py into target environment
    +--> probe runs sections sequentially
    +--> results sent incrementally (per-section)
    +--> agent interprets results, decides follow-up probes
```

Each section is independent. Results are sent incrementally so that if a probe hangs or crashes, you know exactly which one failed.

## Probe Sections

### 1. System Identity

What the environment thinks it is.

| Probe | Command | Why |
|-------|---------|-----|
| Kernel | `uname -a` | OS, arch, kernel version — determines exploit surface |
| Hostname | `hostname` | Often reveals orchestrator info (pod names, sandbox IDs) |
| Identity | `id` | uid/gid — are we root? |
| Users | `cat /etc/passwd` | What accounts exist |
| Boot cmdline | `cat /proc/cmdline` | Reveals VM type, kernel hardening flags |
| CPU | `head -30 /proc/cpuinfo` | Architecture, CPU count |
| Memory | `head -10 /proc/meminfo` | Memory allocation |
| Disk | `df -h` | Mounted filesystems and sizes |
| Environment | `os.environ` | Leaked secrets, trace IDs, cloud metadata |

### 2. Security Controls

What restricts us.

| Probe | Command | Why |
|-------|---------|-----|
| Capabilities | `grep -i cap /proc/self/status` | Decode `CapEff` — key bits: `CAP_SYS_ADMIN` (21), `CAP_NET_RAW` (13), `CAP_SYS_PTRACE` (18), `CAP_NET_ADMIN` (12) |
| Seccomp | `grep Seccomp /proc/self/status` | `2` = filter active, `0` = disabled |
| AppArmor | `cat /proc/self/attr/current` | `unconfined` or profile name |
| SELinux | `getenforce; cat /proc/self/attr/current` | Mode and context |
| No New Privs | `grep NoNewPrivs /proc/self/status` | If 1, can't escalate via setuid |
| SUID binaries | `find / -perm -4000 -type f` | Potential privilege escalation |
| Sudo | `sudo -n id` | Password-less sudo? |
| User namespaces | `cat /proc/sys/user/max_user_namespaces` | If > 0, unprivileged ns creation might be possible |
| Unshare test | `unshare --user --map-root-user id` | Can we actually create namespaces? |

### 3. Namespace Isolation

Which namespaces are we in?

| Probe | Command | Why |
|-------|---------|-----|
| Namespace inodes | `ls -la /proc/self/ns/` | Each namespace has a unique inode. Same inode as host = shared |
| Cgroup | `cat /proc/self/cgroup` | Cgroup path reveals nesting |
| PID visibility | `ls -d /proc/[0-9]*` | How many PIDs visible? Only own = good isolation |
| PID 1 identity | `cat /proc/1/cmdline` | Our init or the host's? |

Key namespaces to check: `mnt`, `pid`, `net`, `user`, `ipc`, `uts`, `cgroup`. Shared `net` means all connections/sockets visible. Shared `user` means real root (within the VM/host).

### 4. Mounts & Filesystem

What's mounted and accessible.

| Probe | Command | Why |
|-------|---------|-----|
| Mounts | `cat /proc/mounts` | Filesystem types, mount options (ro/rw) |
| Mount info | `cat /proc/self/mountinfo` | Detailed: parent mounts, propagation, source paths |
| Root listing | `ls -la /` | What's in the root filesystem |
| Block devices (sysfs) | `ls -la /sys/block/` | Visible disks — reveals VM disk layout |
| Device numbers | `cat /sys/block/*/dev` | Actual major:minor for mknod probes |
| Device nodes | `ls -la /dev/` | Minimal = good isolation. Full `/dev` = weak |
| Overlay source paths | Extracted from mountinfo | Can we traverse the overlay's lowerdir/upperdir? |
| Proc root traversal | `ls -la /proc/1/root/` | Classic container escape path |

### 5. Network

What's reachable.

| Probe | Command | Why |
|-------|---------|-----|
| Interfaces | `ip a` | IPs, MACs, MTU — reveals network topology |
| Routes | `ip route` | Default gateway, reachable subnets |
| ARP table | `ip neigh` | Neighboring hosts — reveals gateway, IMDS MAC |
| DNS config | `cat /etc/resolv.conf` | Nameservers |
| Hosts file | `cat /etc/hosts` | Hostname mappings |
| Listening ports | `ss -tlnp` | Services in our network namespace |
| All connections | `ss -anp` | Established connections, unix sockets |
| Route table (raw) | `cat /proc/net/route` | Fallback when `ip` unavailable |
| Unix socket table | `cat /proc/net/unix` | Raw socket listing with inodes, may show more than `ss` |

Fallbacks: `cat /proc/net/dev` for interfaces, `cat /proc/net/if_inet6` for IPv6 addresses.

### 6. IMDS (Cloud Metadata)

Cloud credential access.

| Probe | Target | Why |
|-------|--------|-----|
| Root | `GET http://169.254.169.254/` | Is IMDS reachable? |
| Metadata listing | `GET /latest/meta-data/` | What metadata is exposed |
| IAM info | `GET /latest/meta-data/iam/info` | Role ARN |
| IAM credentials | `GET /latest/meta-data/iam/security-credentials/` | Temporary AWS credentials |
| Instance identity | `GET /latest/dynamic/instance-identity/document` | Account ID, region, instance type |
| User data | `GET /latest/user-data/` | Bootstrap scripts — often contain secrets |
| IMDSv2 token | `PUT /latest/api/token` | Is IMDSv2 enforced? |

For GCP: `http://metadata.google.internal/computeMetadata/v1/` with `Metadata-Flavor: Google` header.
For Azure: `http://169.254.169.254/metadata/instance?api-version=2021-02-01` with `Metadata: true` header.

Use raw sockets with `Connection: close` and 1-3s timeout.

### 7. Service Reachability

Can we talk to internal services?

| Probe | How | Why |
|-------|-----|-----|
| Unix sockets | `socket.AF_UNIX` connect | Container runtime socket = full control |
| TCP localhost ports | HTTP GET to each listening port from `ss` | Enumerate APIs |

Common unix socket paths to try:
- `/run/containerd/containerd.sock`
- `/var/run/docker.sock`
- `/var/lib/buildkit/buildkitd.sock`
- `/run/dbus/system_bus_socket`
- `/var/run/nri/nri.sock`

Use 1s timeout on TCP probes — firewalled ports hang indefinitely. For ports that respond, enumerate common API paths (`/health`, `/healthz`, `/version`, `/metrics`, `/debug/pprof/`, `/api/v1`).

### 8. Process Information

What else is running?

| Probe | Command | Why |
|-------|---------|-----|
| Process list | `ps -eo pid,ppid,user,stat,vsz,rss,wchan,comm,args` | Full process tree |
| Sched debug | `cat /proc/sched_debug` | Cross-namespace leak — can show all tasks on the system |
| Interrupts | `cat /proc/interrupts` | Hardware info, VM type (virtio = VM) |
| Softirqs | `cat /proc/softirqs` | Workload fingerprinting |
| PID 1 fds | `ls -la /proc/1/fd/` | What files are open |
| PID 1 maps | `cat /proc/1/maps` | Memory mappings reveal host filesystem paths |
| PID 1 map_files | `ls -la /proc/1/map_files/` | Symlinks to mapped files |

**Always use `timeout 3`** on these — some can hang.

### 9. Syscall Surface

What dangerous operations work?

| Probe | How | Risk if succeeds |
|-------|-----|------------------|
| Mount | `mount -t tmpfs none /tmp/x` | Could mount procfs/sysfs to escape |
| mknod + read | `mknod /tmp/x b <major> <minor>` then `dd if=/tmp/x` | Could read raw disks |
| Raw socket | `socket(AF_PACKET, SOCK_RAW, ETH_P_ALL)` | Sniff all network traffic |
| chroot | `chroot /tmp /bin/sh -c "echo ok"` | Root filesystem manipulation |
| ptrace | `libc.ptrace(PTRACE_TRACEME, 0, 0, 0)` | Process injection |
| pivot_root | `libc.syscall(NR_pivot_root, ...)` | Root filesystem swap |
| Kernel module | `modprobe` / `insmod` | Kernel code execution |
| /proc/sys write | `echo 1 > /proc/sys/kernel/sysrq` | Kernel parameter modification |
| sysrq trigger | `echo h > /proc/sysrq-trigger` | Trigger kernel actions |

For mknod: get actual major:minor from `/sys/block/*/dev`, not hardcoded values. Use `od -A x -t x1z` to hex-dump reads (`xxd` is often missing in slim images).

### 10. Packet Capture

If raw sockets work (section 9), sniff traffic.

```python
s = socket.socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))
# Capture for N seconds
# Parse: ethernet (14B) -> IP header -> TCP header -> payload
# Log: src_ip:port -> dst_ip:port, decode payload as text
# Focus on: IMDS (169.254.169.254), any HTTP plaintext
```

Capture duration: 15-30 seconds. IMDS credential refresh is typically every 5-15 minutes so success is timing-dependent. Longer captures increase likelihood.

### 11. Kernel Information

Kernel state leaks.

| Probe | Command | Why |
|-------|---------|-----|
| Kernel symbols | `head -20 /proc/kallsyms` | Non-zero addresses = KASLR defeated |
| Kernel config | `cat /proc/config.gz` | Full kernel build configuration |
| Slab info | `head -5 /proc/slabinfo` | Kernel heap layout |
| Kernel keys | `cat /proc/keys` | Kernel keyring contents |
| Key users | `cat /proc/key-users` | UIDs with kernel keys — leaks host UID existence |

### 12. Cgroup Escape

Classic container escape vectors.

| Probe | Command | Why |
|-------|---------|-----|
| Release agent | `cat /sys/fs/cgroup/release_agent` | cgroupv1 escape (write host binary path) |
| Notify on release | `cat /sys/fs/cgroup/notify_on_release` | If 1 + writable, escape possible |
| Cgroup procs | `cat /sys/fs/cgroup/cgroup.procs` | PIDs in our cgroup |
| Controllers | `cat /sys/fs/cgroup/cgroup.controllers` | Available controllers |

Only relevant for cgroupv1. cgroupv2 does not have `release_agent`.

### 13. Secrets & Config Files

Look for credentials left behind.

| Probe | Path | Why |
|-------|------|-----|
| Docker socket | `/var/run/docker.sock` | Full container control |
| Containerd config | `/etc/containerd/config.toml` | Runtime configuration |
| Shadow file | `/etc/shadow` | Password hashes |
| SSH keys | `find / -name authorized_keys -o -name id_rsa -o -name id_ed25519` | SSH access |
| Cloud init | `/var/lib/cloud/instance/user-data.txt` | Bootstrap scripts with secrets |
| AWS config | `/root/.aws/credentials`, `/root/.aws/config` | Static AWS credentials |
| GCP service account | `/var/run/secrets/...`, `GOOGLE_APPLICATION_CREDENTIALS` env | GCP credentials |
| K8s service account | `/var/run/secrets/kubernetes.io/serviceaccount/token` | Kubernetes API access |

## Implementation Notes

### Safety

- **Send results per-section** — if a probe hangs or crashes, you know which one
- **Timeout everything** — `timeout 3-10` on shell commands, `socket.settimeout()` on network probes
- **Run ctypes probes in subprocesses** — `subprocess.run(['python3', '-c', '...'])`. A segfault in-process kills the entire probe with no output
- **Never PTRACE_ATTACH on PID 1** — stops the target process and hangs the container
- **Use `Connection: close`** on HTTP probes so they don't hang waiting for more data

### Portability

- `od -A x -t x1z` is POSIX-portable; `xxd` is often missing in slim images
- `cat /proc/net/dev` works as fallback when `ip` is unavailable
- `cat /proc/net/route` works as fallback when `ip route` is unavailable
- `procps` needed for `ps`, `iproute2` needed for `ip`/`ss` — probe should work without them using `/proc` fallbacks

### Output Format

Each section reports a JSON object with a `section` key:

```json
{"section": "1_system", "uname": "...", "hostname": "...", ...}
{"section": "2_security", "caps": "...", "seccomp": "...", ...}
```

Transport is pluggable: webhook POST, stdout, file, or direct return to calling agent.

### Syscall Numbers

Architecture-dependent. Common ones:

| Syscall | x86_64 | aarch64 |
|---------|--------|---------|
| pivot_root | 155 | 41 |
| mount | 165 | 21 |
| ptrace | 101 | 117 |

### Capability Bit Reference

```
CAP_NET_ADMIN   = 12    CAP_SYS_ADMIN  = 21
CAP_NET_RAW     = 13    CAP_SYS_PTRACE = 18
CAP_SYS_MODULE  = 16    CAP_MKNOD      = 27
CAP_SYS_CHROOT  = 18    CAP_DAC_OVERRIDE = 1
```

Decode `CapEff` hex to check which bits are set.