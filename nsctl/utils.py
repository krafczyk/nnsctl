from enum import IntEnum, unique
import os


# Classes for managing privileges
@unique
class Capability(IntEnum):
    CAP_CHOWN            = 0
    CAP_DAC_OVERRIDE     = 1
    # … (fill in 0–37 from linux/capability.h) …
    CAP_SYS_ADMIN        = 21
    CAP_NET_ADMIN        = 12
    # etc.


class Capabilities:
    """
    Parse /proc/self/status for CapInh, CapPrm, CapEff.
    Exposes .inheritable, .permitted, .effective as ints.
    """
    inheritable: int
    permitted: int
    effective: int

    def __init__(self, pid: int|None=None):
        if pid is None:
            pid =  os.getpid()
        self._read_status(pid)

    def _read_status(self, pid: int):
        path = f"/proc/{pid}/status"
        caps = {}
        with open(path) as f:
            for line in f:
                for field in ("CapInh:", "CapPrm:", "CapEff:"):
                    if line.startswith(field):
                        # hex string → int
                        caps[field] = int(line.split()[1], 16)
        self.inheritable = caps["CapInh:"]
        self.permitted   = caps["CapPrm:"]
        self.effective   = caps["CapEff:"]

    def has(self, cap: Capability, which: str = "effective") -> bool:
        """
        which ∈ {'inheritable','permitted','effective'}
        """
        mask: int = getattr(self, which)
        return bool(mask & (1 << cap))


# Required capabilities for each namespace operation
REQUIRED = {
    "netns":  [Capability.CAP_NET_ADMIN, Capability.CAP_SYS_ADMIN],
    "mntns":  [Capability.CAP_SYS_ADMIN],
    "pidns":  [Capability.CAP_SYS_ADMIN],
}


def check_ops(ops: list[str]) -> bool:
    caps = Capabilities()
    if os.geteuid() == 0:
        return True
    for op in ops:
        for req in REQUIRED[op]:
            if not caps.has(req):
                return False
    return True
