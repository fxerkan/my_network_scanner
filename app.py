#!/usr/bin/env python3
"""Backwards-compatible entry point. Real app lives in mynes/web/app.py."""

from mynes.web.app import app, main  # noqa: F401  (WSGI servers import `app`)

if __name__ == '__main__':
    main()
