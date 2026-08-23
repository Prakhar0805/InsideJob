"""Top-level shim so `python -m gapfuzz` works from the repo root.

The implementation lives in `src.gapfuzz`; this package just re-exports it so
the documented command line matches how the code is laid out.
"""

from src.gapfuzz import *  # noqa: F401,F403
