
import argparse

from mantis.core.config import MantisConfig


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="mantis",
        description="MANTIS — API security testing framework",
    )

    parser.add_argument(
        "--version",
        action="version",
        version="MANTIS 0.1.0",
    )

    parser.parse_args()

    # Verify that the default configuration is valid.
    MantisConfig()


if __name__ == "__main__":
    main()
