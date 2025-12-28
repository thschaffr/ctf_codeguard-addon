import json
import os
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Tuple

import requests
from flask import Flask, jsonify, render_template, request

TARGET_ORIGIN = os.environ.get("TARGET_ORIGIN", "http://localhost:8080").rstrip("/")
TARGET_APP_PATH = os.environ.get("TARGET_APP_PATH", "/app").rstrip("/")
APP_BASE = f"{TARGET_ORIGIN}{TARGET_APP_PATH}"
UPLOAD_BASE = f"{TARGET_ORIGIN}/uploads"

FLAGS = {
    "sql": os.environ.get("FLAG_SQL", "FLAG{prepared_statements_rock}"),
    "idor": os.environ.get("FLAG_IDOR", "FLAG{check_your_permissions}"),
    "rce": os.environ.get("FLAG_RCE", "FLAG{no_more_php_uploads}"),
}

RESET_SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "reset.sh"

app = Flask(__name__, template_folder="templates", static_folder="static")


def verify_sql_injection() -> Tuple[bool, str]:
    session = requests.Session()
    login_url = f"{APP_BASE}/login.php"
    payload = {
        "user": "' OR '1'='1' -- ",
        "pass": "irrelevant",
    }
    try:
        resp = session.post(login_url, data=payload, allow_redirects=False, timeout=8)
    except requests.RequestException as exc:
        return False, f"Request failed: {exc}"

    location = resp.headers.get("Location", "")
    if resp.status_code in (301, 302) and "profile.php" in location:
        return False, "SQL injection still allows authentication bypass."

    # Some fixes may still return 302 but to login with error parameter
    if resp.status_code == 200 and "Bad credentials" in resp.text:
        return True, FLAGS["sql"]

    if resp.status_code in (301, 302):
        return False, f"Unexpected redirect: {location}"

    return True, FLAGS["sql"]


def perform_login(session: requests.Session, username: str, password: str) -> bool:
    login_url = f"{APP_BASE}/login.php"
    try:
        resp = session.post(
            login_url,
            data={"user": username, "pass": password},
            allow_redirects=True,
            timeout=8,
        )
    except requests.RequestException:
        return False
    return resp.status_code == 200 and "Bad credentials" not in resp.text


def verify_idor() -> Tuple[bool, str]:
    session = requests.Session()
    if not perform_login(session, "alex", "alexgoestociscolive"):
        return False, "Unable to authenticate with baseline credentials."

    try:
        resp = session.get(f"{APP_BASE}/profile.php?id=2", timeout=8)
    except requests.RequestException as exc:
        return False, f"Request failed: {exc}"

    if "FLAG{whose_data_is_it_anyway}" in resp.text or "FLAG{" in resp.text and "FLAG{alex_should_parameterize}" not in resp.text:
        return False, "Profile endpoint still exposes other users' data."

    return True, FLAGS["idor"]


def verify_upload() -> Tuple[bool, str]:
    session = requests.Session()
    if not perform_login(session, "alex", "alexgoestociscolive"):
        return False, "Unable to authenticate with baseline credentials."

    marker = f"VERIFICATION_{int(time.time())}"
    filename = f"verify_{int(time.time())}.php"
    files = {
        "file": (filename, f"<?php echo '{marker}'; ?>", "application/x-php"),
    }

    try:
        upload_resp = session.post(f"{APP_BASE}/upload.php", files=files, timeout=10)
    except requests.RequestException as exc:
        return False, f"Upload request failed: {exc}"

    if upload_resp.status_code >= 500:
        return False, "Upload endpoint returned server error."

    try:
        shell_resp = session.get(f"{UPLOAD_BASE}/{filename}", timeout=8)
    except requests.RequestException as exc:
        return True, FLAGS["rce"]  # If inaccessible, treat as fixed

    # Determine whether the uploaded payload executed or was served as plain text.
    body = shell_resp.text or ""
    body_lower = body.lower()

    # If the server returns PHP source (contains the '<?php' tag), treat as non-executable → pass.
    if "<?php" in body_lower:
        return True, FLAGS["rce"]

    # If we see the expected marker without PHP tags, it likely executed → fail.
    if marker in body and "<?php" not in body_lower:
        if body.strip() == marker:
            return False, "Uploaded content executed on the server."
        return False, "Uploaded content is still executable."

    return True, FLAGS["rce"]


VERIFIERS = {
    "sql": verify_sql_injection,
    "idor": verify_idor,
    "rce": verify_upload,
}


@app.route("/")
def index():
    return render_template("index.html")


@app.post("/api/verify/<challenge>")
def api_verify(challenge: str):
    verifier = VERIFIERS.get(challenge)
    if verifier is None:
        return jsonify({"success": False, "message": f"Unknown challenge '{challenge}'."}), 400

    success, detail = verifier()
    response = {"success": success}
    if success:
        response["flag"] = detail
    else:
        response["message"] = detail
    return jsonify(response)


@app.post("/api/reset")
def api_reset():
    if not RESET_SCRIPT.exists():
        return jsonify({"success": False, "message": "Reset script not found."}), 500

    try:
        result = subprocess.run(
            ["/bin/bash", str(RESET_SCRIPT)],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            check=True,
        )
        output = result.stdout.strip()
    except subprocess.CalledProcessError as exc:
        cleaned_error = (exc.stdout or str(exc)).strip()
        # Strip legacy builder warning from error as well
        if cleaned_error.startswith("DEPRECATED: The legacy builder is deprecated"):
            cleaned_error = "Docker build failed: legacy builder no longer supported. Install buildx on host."
        return jsonify({"success": False, "message": cleaned_error}), 500

    # Clean legacy builder warning from the success output
    if output.startswith("DEPRECATED:"):
        output_lines = output.splitlines()
        output = "\n".join(line for line in output_lines if not line.startswith("DEPRECATED:"))

    # Always return a short success message to the UI
    return jsonify({
        "success": True,
        "message": "Environment reset successfully."
    })


@app.post("/api/rebuild")
def api_rebuild():
    rebuild_cmd = [
        "/bin/bash",
        "-lc",
        "docker rm -f vuln_app >/dev/null 2>&1 || true && "
        "docker build -t vuln_app /workspace/idea_1 && "
        "docker run -d -p 8080:80 --name vuln_app vuln_app"
    ]

    try:
        result = subprocess.run(
            rebuild_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            check=True,
        )
        output = result.stdout.strip()
    except subprocess.CalledProcessError as exc:
        cleaned_error = (exc.stdout or str(exc)).strip()
        return jsonify({"success": False, "message": cleaned_error}), 500

    if output.startswith("DEPRECATED:"):
        output_lines = output.splitlines()
        output = "\n".join(line for line in output_lines if not line.startswith("DEPRECATED:"))

    return jsonify({
        "success": True,
        "message": "Vulnerable app rebuilt and restarted."
    })


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)

