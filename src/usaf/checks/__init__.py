# Check plugins are auto-discovered via the registry.
# Importing every submodule in usaf.checks triggers @register_check
# decorators, populating the plugin registry.
#
# If a new check is not being discovered, verify:
#   1. It has @register_check decorator
#   2. The module is inside usaf.checks (or a subdirectory)
#  No __init__.py edits needed.

from usaf.core.registry import discover_checks

discover_checks()
