"""Linux-only SETools supervisor: bounded child, group termination and orphan reaping."""
import ctypes
import os
import resource
import selectors
import signal
import subprocess
import sys
import time

MAX_OUTPUT = 1024 * 1024
MAX_MEMORY = 512 * 1024 * 1024


def limits(cpu):
    resource.setrlimit(resource.RLIMIT_CPU, (cpu, cpu))
    resource.setrlimit(resource.RLIMIT_AS, (MAX_MEMORY, MAX_MEMORY))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


def interrupted(signum, frame):
    raise RuntimeError("Policy subprocess supervisor interrupted")


def run(command, wall, cpu):
    # Subreaping is local to this supervisor, not the Rails application process.
    if ctypes.CDLL(None, use_errno=True).prctl(36, 1, 0, 0, 0) != 0:
        raise RuntimeError("Policy subprocess descendant reaping is unavailable")
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    deadline = time.monotonic() + wall
    child = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, start_new_session=True,
                             preexec_fn=lambda: limits(cpu))
    output = [bytearray(), bytearray()]
    total = 0
    try:
        with selectors.DefaultSelector() as selector:
            for index, pipe in enumerate((child.stdout, child.stderr)):
                os.set_blocking(pipe.fileno(), False)
                selector.register(pipe, selectors.EVENT_READ, index)
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise RuntimeError("Policy subprocess exceeded 30-second runtime bound")
                for key, _ in selector.select(remaining):
                    chunk = os.read(key.fileobj.fileno(), 65536)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    total += len(chunk)
                    if total > MAX_OUTPUT:
                        raise RuntimeError("Policy subprocess exceeded 1 MiB combined output bound")
                    output[key.data].extend(chunk)
        try:
            status = child.wait(timeout=max(0, deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            raise RuntimeError("Policy subprocess exceeded 30-second runtime bound") from None
        if status < 0:
            raise RuntimeError("Policy subprocess terminated by signal/resource limit")
        if status:
            # sesearch can put load failures on stdout. Keep them as diagnostics,
            # never successful parser input; the combined output bound still holds.
            diagnostic = bytes(output[1]) + bytes(output[0])
            return b"", diagnostic, status
        return bytes(output[0]), bytes(output[1]), status
    finally:
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        # Kill even on successful leader exit: a helper must not leave background children.
        try:
            os.killpg(child.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        child.wait()
        child.stdout.close()
        child.stderr.close()
        while True:
            try:
                pid, _ = os.waitpid(-1, os.WNOHANG)
            except ChildProcessError:
                break
            if pid:
                continue
            # An adopted descendant may have escaped the original process group.
            # These PIDs belong only to this dedicated subreaper, never to Rails.
            with open(f"/proc/self/task/{os.getpid()}/children") as file:
                descendants = [int(value) for value in file.read().split()]
            for descendant in descendants:
                try:
                    os.kill(descendant, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            os.waitpid(-1, 0)


if __name__ == "__main__":
    try:
        wall, cpu = float(sys.argv[1]), int(sys.argv[2])
        if not 0 < wall <= 30 or not 0 < cpu <= 30:
            raise ValueError("Policy subprocess limits may only be lowered")
        stdout, stderr, code = run(sys.argv[3:], wall, cpu)
    except FileNotFoundError:
        stdout, stderr, code = b"", b"SETools executable is unavailable", 2
    except Exception as error:
        stdout, stderr, code = b"", str(error).encode("utf-8")[:500], 1
    sys.stdout.buffer.write(stdout)
    sys.stderr.buffer.write(stderr)
    sys.exit(code)
