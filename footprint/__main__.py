"""Allow `python -m footprint`."""

from .cli import main

if __name__ == "__main__":
    raise SystemExit(main())
