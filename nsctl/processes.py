import sys
import os, shlex, subprocess, shutil
import psutil
from collections.abc import Mapping
from typing import cast, Any, Literal

from nsctl.config import Namespaces
from nsctl.utils import get_uid, get_gid


def _exec_cmd(cmd: list[str] | str,
              *,
              # orthogonal switches
              detach: bool = False,
              capture_output: bool = False,
              check: bool = False,
              dry_run: bool = False,
              env: Mapping[str, str] | None = None,
              # namespace
              ns_pid: int | None = None,
              working_dir: str | None = None,
              # privilege
              escalate: Literal["sudo", "pkexec", None] = None,
              as_user: str | None = None
              ) -> subprocess.CompletedProcess[str] | subprocess.Popen[str] | None:
    """
    Bottom level executor
    * `detach=True` -> returns immediately with `popen` handle; `capture_output`
                       must be false
    * `ns_pid`      -> if provided, prepends `nsenter -t <pid> --all --`.
    * `escalate`    -> prepend `sudo -n` or `pkexec` **once**, *before* nsenter.
    * `as_user`     -> translate to `--setuid/--setgid` when using nsenter.
    """

    # ----------------------- validate --------------------------
    if detach and capture_output:
        raise ValueError("Cannot use detach=True with capture_output=True.")
    if isinstance(cmd, str):
        cmd_args: list[str] = shlex.split(cmd)
    else:
        cmd_args = list(cmd)

    # ----------------------- nsenter --------------------------
    if ns_pid is not None:
        ns_cmd = ["nsenter", "-t", str(ns_pid), "--all"]
        if working_dir:
            ns_cmd.append(f"--wd={working_dir}")
        if as_user:
            uid = get_uid(as_user)
            gid = get_gid(as_user)
            ns_cmd += [f"--setuid={uid}", f"--setgid={gid}"]
        ns_cmd.append("--")
        cmd_args = ns_cmd + cmd_args

    # ----------------------- escalate --------------------------
    if escalate is not None:
        helper = shutil.which(escalate)
        if helper is None:
            raise RuntimeError(f"{escalate} not found in PATH; cannot escalate")
        cmd_args = [helper, "-n"] + cmd_args

    # ----------------------- dry-run --------------------------
    if dry_run:
        print("DRY-RUN:", " ".join(cmd_args))
        return None

    # ----------------------- execution path --------------------------
    if detach:
        return subprocess.Popen(
            cmd_args,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=env,
            start_new_session=True,
            text=True,
        )
    return subprocess.run(
        cmd_args,
        text=True,
        capture_output=capture_output,
        env=env,
        check=check
    )


def run_cmd(cmd: list[str] | str,
            capture_output: bool=False,
            shell: bool=False,
            dry_run: bool=False,
            skip_error: bool=False,
            try_sudo: bool=False
           ) -> None | subprocess.CompletedProcess[str]:
    """
    Runs a command, and if try_sudo=True and it fails with a permission error,
    retries exactly once with sudo.
    """
    # if it's a string but not using shell, split it
    if isinstance(cmd, str) and not shell:
        cmd = cmd.split()

    # dry run?
    if dry_run:
        printable = cmd if isinstance(cmd, str) else " ".join(cmd)
        print("DRY-RUN:", printable)
        return None

    try:
        return subprocess.run(
            cmd,
            capture_output=capture_output,
            text=True,
            check=True,
            shell=shell
        )

    except subprocess.CalledProcessError as e:
        if skip_error:
            print(f"Warning: Command failed with error: {e}", file=sys.stderr)
            return None

        # only consider sudo-retry if opted in and not running as root
        if try_sudo and os.geteuid() != 0:
            out:str = (cast(str, e.stderr) or "") + (cast(str, e.stdout) or "")
            if ("Permission denied" in out
                or "Operation not permitted" in out
                or e.returncode in (1, 126)
            ):
                # build the sudo command
                if shell:
                    base = cmd if isinstance(cmd, str) else " ".join(cmd)
                    sudo_cmd = f"sudo {base}"
                else:
                    sudo_cmd = ["sudo"] + (cmd if isinstance(cmd, list) else cmd.split())
                print(f"Retrying with sudo: {sudo_cmd}", file=sys.stderr)
                # retry once, but disable further sudo attempts
                return run_cmd(
                    sudo_cmd,
                    capture_output=capture_output,
                    shell=shell,
                    dry_run=dry_run,
                    skip_error=skip_error,
                    try_sudo=False
                )

        # still failed (or not a permission error)
        printable = cmd if isinstance(cmd, str) else " ".join(cmd)
        print(f"Error running command: {printable}", file=sys.stderr)
        print(cast(str,e.stderr) or e, file=sys.stderr)
        return None


def run_cmd_sudo(*args: Any, **kwargs: Any): # pyright: ignore[reportAny,reportExplicitAny]
    return run_cmd(*args, try_sudo=True, **kwargs) # pyright: ignore[reportAny] 


def run_in_namespace(
        pid: int,
        command: list[str]|str,
        *,
        net: bool = False,
        mount: bool = False,
        pid_ns: bool = False,
        ipc: bool = False,
        uts: bool = False,
        user_ns: bool = False,
        cgroup: bool = False,
        time_ns: bool = False,
        namespaces: Namespaces|None = None,
        as_user: str|None = None,
        dry_run: bool = False,
        working_dir: str|None = None,
    ) -> subprocess.CompletedProcess[str] | None:
    """
    Execute `command` inside the namespaces of the given `pid` via nsenter.
    
    Flags correspond to the nsenter options:
      net, mount, pid_ns, ipc, uts, user_ns, cgroup, time_ns.
    If `as_user` is provided (e.g. "matthew"), we ssh-u to that UID/GID
    inside the namespace (requires sudo). Otherwise, if you're root it'll
    just call nsenter directly.
    """
    # 1) build the list of nsenter flags
    ns_args: list[str] = []
    if namespaces is not None:
        net = namespaces.net or net
        mount = namespaces.mount or mount
        pid_ns = namespaces.pid or pid_ns
        ipc = namespaces.ipc or ipc
        uts = namespaces.uts or uts
        user_ns = namespaces.user or user_ns
        cgroup = namespaces.cgroup or cgroup
        time_ns = namespaces.time or time_ns
 
    if net:       ns_args.append("--net")
    if mount:     ns_args.append("--mount")
    if pid_ns:    ns_args.append("--pid")
    if ipc:       ns_args.append("--ipc")
    if uts:       ns_args.append("--uts")
    if user_ns:   ns_args.append("--user")
    if cgroup:    ns_args.append("--cgroup")
    if time_ns:   ns_args.append("--time")
    if working_dir:
        ns_args.append(f"--wd={working_dir}")

    base = ["nsenter", "-t", str(pid)] + ns_args

    cmd: list[str] = []

    if type(command) is str:
        cmd = command.strip().split()

    # 2) if we're root, just run it
    if os.geteuid() == 0:
        cmd = base + cmd
        return run_cmd(cmd, dry_run=dry_run)

    # 3) otherwise wrap in sudo
    sudo_cmd = base.copy()
    if as_user:
        # resolve uid/gid
        res = run_cmd(["id", "-u", as_user], capture_output=True)
        if res is None:
            raise RuntimeError(f"User {as_user} not found")
        uid = res.stdout.strip()
        res = run_cmd(["id", "-g", as_user], capture_output=True)
        if res is None:
            raise RuntimeError(f"User {as_user} not found")
        gid = res.stdout.strip()
        sudo_cmd += [f"--setuid={uid}", f"--setgid={gid}"]
    sudo_cmd += ["--"] + cmd
    return run_cmd_sudo(sudo_cmd, dry_run=dry_run)


def find_bottom_children(pid: int) -> list[psutil.Process]:
    """
    Recursively returns a list of all leaf (bottom-most) processes
    in the process tree rooted at `pid`.
    """
    try:
        process = psutil.Process(pid)
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return []

    children = process.children()
    if not children:
        # This process has no children, so it's a bottom-most process
        return [process]

    # Otherwise, collect bottom-most children of each child
    bottom: list[psutil.Process] = []
    for child in children:
        bottom.extend(find_bottom_children(child.pid))
    return bottom


def process_exists(pid: int):
    if os.path.exists(f"/proc/{pid}"):
        try:
            process = psutil.Process(pid)
            return process.is_running()
        except psutil.NoSuchProcess:
            return False
