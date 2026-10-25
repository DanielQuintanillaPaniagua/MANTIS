"""Entry point for `python -m mantis`."""

import sys

from mantis.cli.main import main

if __name__ == "__main__":
    sys.exit(main())