"""
CLI execution entry point when invoked via `python -m uncloak`.
"""

import sys
from uncloak.cli.parser import main

if __name__ == "__main__":
    sys.exit(main())
