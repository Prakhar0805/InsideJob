"""Top-level shim so `python -m policy_corpus` works from the repo root.

The implementation lives in `src.policy_corpus`; this package re-exports it and
provides the CLI, matching the layout of the `gapfuzz` shim.
"""

from src.policy_corpus import *  # noqa: F401,F403
from src.policy_corpus import (  # noqa: F401
    PolicyRecord,
    dry_run,
    generate_one,
    load_records,
    model_slug,
    run_generation,
    status,
    write_summary,
)
