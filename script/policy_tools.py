"""Load exact policy bytes without confusing toolchain support with validity."""
import sys

try:
    import setools
except ImportError:
    print("SETools Python bindings are unavailable", file=sys.stderr)
    sys.exit(2)


def load_policy(path):
    try:
        return setools.SELinuxPolicy(path)
    except setools.exception.InvalidPolicy as error:
        print(f"SETools {setools.__version__} could not load the policy. The installed "
              "SETools/libsepol toolchain may not support its format; malformed policy "
              f"bytes are not established. {error}", file=sys.stderr)
        sys.exit(1)
