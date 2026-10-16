"""Run the admin portal. Bind localhost unless the platform sets a bind address."""

from __future__ import annotations

import os

import uvicorn

from presidio_admin.app import create_app_from_env


def main() -> None:
    app = create_app_from_env()
    host = os.environ.get("PRM_ADMIN_BIND", "127.0.0.1")
    port = int(os.environ.get("PRM_ADMIN_PORT", "8080"))
    uvicorn.run(app, host=host, port=port, access_log=False, log_level="info")


if __name__ == "__main__":
    main()
