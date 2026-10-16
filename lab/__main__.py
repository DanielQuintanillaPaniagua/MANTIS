"""Entry point for `python -m lab`.

Binds to 127.0.0.1 only. Never 0.0.0.0.
"""

import uvicorn


def main() -> None:
    uvicorn.run(
        "lab.app:app",
        host="127.0.0.1",
        port=8000,
        reload=False,
        log_level="info",
    )


if __name__ == "__main__":
    main()