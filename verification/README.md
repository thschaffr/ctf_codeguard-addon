# Verification Service

A lightweight portal for confirming CTF challenge fixes. The service exposes a web UI with three automated checks and a reset action that rebuilds the vulnerable environment.

## Features

- **SQL Injection** – Tries to bypass login using a classic `' OR '1'='1' --` payload. Passes when the login flow refuses the injection.
- **IDOR** – Logs in with baseline credentials and attempts to fetch another user’s profile (`id=2`). Passes when access is denied or sanitized.
- **Upload Execution** – Uploads a PHP payload and requests it from `/uploads/<file>`. Passes when the payload cannot be executed.
- **Reset Environment** – Calls `scripts/reset.sh`, which rebuilds the vulnerable app container and restarts it.

Flags for each challenge are returned when the corresponding verification succeeds.

## Configuration

Environment variables (defaults shown):

```
TARGET_ORIGIN=http://localhost:8080
TARGET_APP_PATH=/app
FLAG_SQL=FLAG{prepared_statements_rock}
FLAG_IDOR=FLAG{check_your_permissions}
FLAG_RCE=FLAG{no_more_php_uploads}
APP_SOURCE_DIR=/workspace/idea_1
APP_IMAGE_NAME=vuln_app
APP_CONTAINER_NAME=vuln_app
APP_PORT_MAPPING=8080:80
```

- `TARGET_ORIGIN` – Base URL (scheme + host + port) for the vulnerable app.
- `TARGET_APP_PATH` – Path prefix where the PHP app lives (e.g., `/app`).
- Flags – Customize per challenge.
- `APP_SOURCE_DIR` / `APP_IMAGE_NAME` / `APP_CONTAINER_NAME` / `APP_PORT_MAPPING` – Used by `scripts/reset.sh` to rebuild & relaunch the target container. The verification container must have access to the Docker socket (`-v /var/run/docker.sock:/var/run/docker.sock`) for reset to work.

## Docker Usage

Build and run the verification portal:

```bash
cd verification
docker build -t challenge-verifier .

docker run -d \
  --name challenge-verifier \
  --net host \  # or configure networking appropriately
  -e TARGET_ORIGIN=http://localhost:8080 \
  -e APP_SOURCE_DIR=/path/to/idea_1 \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v /path/to/ctf_codeguard:/workspace \
  challenge-verifier
```

Access the UI at `http://localhost:5000` (or the mapped port).

## Reset Script

`scripts/reset.sh` performs:

1. `docker rm -f $APP_CONTAINER_NAME`
2. `docker build -t $APP_IMAGE_NAME $APP_SOURCE_DIR`
3. `docker run -d -p $APP_PORT_MAPPING --name $APP_CONTAINER_NAME $APP_IMAGE_NAME`

Ensure the specified paths are reachable from inside the verification container (mount them if necessary).

> **Important:** The reset button requires the Docker socket to be mounted and (optionally) the `idea_1` directory mounted at `/workspace/idea_1` so rebuilding starts from a clean copy of the vulnerable app.

