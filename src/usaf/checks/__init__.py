# Check plugins are auto-discovered via the registry.
# Import check modules to trigger registration.
# Explicit imports ensure plugins are available before CLI runs.

from usaf.checks.system import kernel_checks
from usaf.checks.system import ssh_checks
from usaf.checks.users import user_checks
from usaf.checks.network import port_checks
from usaf.checks.permissions import suid_checks
