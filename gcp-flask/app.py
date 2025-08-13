import base64
import json
import io
import mimetypes
import os
from datetime import datetime
from typing import Dict, List, Optional

import google.auth
import logging
import tempfile
from flask import (
    Flask,
    flash,
    redirect,
    render_template,
    request,
    send_file,
    url_for,
    session,
)
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from googleapiclient.http import MediaFileUpload, MediaIoBaseDownload
from google_auth_oauthlib.flow import Flow
from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request


ALLOWED_EXTENSIONS = {"txt", "csv", "xlsx", "xls", "pdf", "png", "jpg", "jpeg", "gif", "tif", "tiff", "mp4", "mov", "avi", "mkv", "webm", "mpeg", "mpg"}
TEAM_PASSWORDS: Dict[str, str] = {
    "team1": "uAsZlhwSHhKLfUePeArnEETI",
    "team2": "uAsZlhwSHhKLfUePeArnEETI",
    "team3": "uAsZlhwSHhKLfUePeArnEETI",
    "team4": "uAsZlhwSHhKLfUePeArnEETI",
}

app = Flask(__name__, template_folder="templates")
app.config["SECRET_KEY"] = os.environ.get("FLASK_SECRET", "change-this-secret-key")
app.config["MAX_CONTENT_LENGTH"] = 500 * 1024 * 1024  # 500MB limit

logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"))

# Admin password for saving final results
# You can hard-code it here; env var ADMIN_PASSWORD (if set) will override.
ADMIN_PASSWORD_CONSTANT = "admin"
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "") or ADMIN_PASSWORD_CONSTANT


def allowed_file(filename: str) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

TOKEN_PATH = os.path.join(tempfile.gettempdir(), "drive_user_token.json")


class NeedsUserAuth(Exception):
    pass


def _write_client_secret_to_temp() -> str:
    b64 = os.environ.get("CLIENT_SECRET_JSON_B64", "")
    if not b64:
        raise NeedsUserAuth("CLIENT_SECRET_JSON_B64 not set")
    try:
        raw = base64.b64decode(b64)
        path = os.path.join(tempfile.gettempdir(), "client_secret.json")
        with open(path, "wb") as f:
            f.write(raw)
        return path
    except Exception as e:
        raise NeedsUserAuth(f"Invalid CLIENT_SECRET_JSON_B64: {e}")


def _is_truthy(val: str) -> bool:
    return str(val).strip().lower() in {"1", "true", "yes", "on"}

# If set truthy, clear final_result.txt from each team folder once per instance
CLEAR_FINAL_ON_START = _is_truthy(os.environ.get("CLEAR_FINAL_ON_START", "0"))
_CLEAR_COMPLETED = False


def _delete_final_for_team(service, team: str) -> None:
    try:
        folder_id = get_or_create_team_folder(service, team)
        f = find_file_by_name(service, folder_id, "final_result.txt")
        if f:
            # Move to trash
            service.files().update(fileId=f["id"], body={"trashed": True}, supportsAllDrives=True).execute()
            logging.info("Cleared final_result.txt for %s", team)
    except Exception:
        logging.exception("Failed clearing final_result for %s", team)


def _maybe_clear_final_results(service=None) -> None:
    global _CLEAR_COMPLETED
    if not CLEAR_FINAL_ON_START or _CLEAR_COMPLETED:
        return
    try:
        svc = service or get_drive_service()
    except NeedsUserAuth:
        # Will retry later when auth is available
        return
    for team in TEAM_PASSWORDS.keys():
        _delete_final_for_team(svc, team)
    _CLEAR_COMPLETED = True


def _ensure_user_token_from_env() -> None:
    """Load a pre-authorized user OAuth token from env if provided.

    Set USER_OAUTH_TOKEN_JSON_B64 to the base64-encoded contents of
    a drive_user_token.json previously obtained via /authorize.
    Useful for Cloud Run so instances can act as your account without
    interactive consent per instance.
    """
    if os.path.exists(TOKEN_PATH):
        return
    b64 = os.environ.get("USER_OAUTH_TOKEN_JSON_B64", "")
    if not b64:
        return
    try:
        raw = base64.b64decode(b64)
        with open(TOKEN_PATH, "wb") as f:
            f.write(raw)
        logging.info("Loaded user OAuth token from env into %s", TOKEN_PATH)
    except Exception:
        logging.exception("Failed to load USER_OAUTH_TOKEN_JSON_B64")


def _load_user_credentials() -> Optional[Credentials]:
    # First, hydrate from env if available (for Cloud Run)
    _ensure_user_token_from_env()
    if os.path.exists(TOKEN_PATH):
        try:
            creds = Credentials.from_authorized_user_file(TOKEN_PATH, scopes=["https://www.googleapis.com/auth/drive"])
            if creds and creds.expired and creds.refresh_token:
                creds.refresh(Request())
                with open(TOKEN_PATH, "w") as f:
                    f.write(creds.to_json())
            if creds and creds.valid:
                return creds
        except Exception:
            logging.exception("Failed to load/refresh user token; will require re-auth")
    return None


def get_drive_service():
    # 1) Prefer User OAuth via cached token (avoids SA My Drive quota limits)
    creds = _load_user_credentials()
    if creds:
        logging.info("Drive auth method: User OAuth (cached token)")
        return build("drive", "v3", credentials=creds, cache_discovery=False)

    # 2) Service account via JSON (env base64 or GOOGLE_APPLICATION_CREDENTIALS)
    ga_cred = os.environ.get("GOOGLE_APPLICATION_CREDENTIALS")
    b64 = os.environ.get("SERVICE_ACCOUNT_JSON_B64", "")
    if not ga_cred and b64:
        try:
            raw = base64.b64decode(b64)
            cred_path = os.path.join(tempfile.gettempdir(), "service_account.json")
            with open(cred_path, "wb") as f:
                f.write(raw)
            os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = cred_path
            ga_cred = cred_path
            logging.info("Drive auth: using service account JSON from env (written to %s)", cred_path)
        except Exception:
            logging.exception("Failed to set up SERVICE_ACCOUNT_JSON_B64; falling back to ADC/User OAuth")
    if ga_cred:
        scopes = ["https://www.googleapis.com/auth/drive"]
        creds, _ = google.auth.default(scopes=scopes)
        logging.info("Drive auth method: Service Account (GOOGLE_APPLICATION_CREDENTIALS)")
        return build("drive", "v3", credentials=creds, cache_discovery=False)

    # 3) ADC (e.g., Cloud Run) or ask for user auth locally
    try:
        scopes = ["https://www.googleapis.com/auth/drive"]
        creds, _ = google.auth.default(scopes=scopes)
        logging.info("Drive auth method: Application Default Credentials (ADC)")
        return build("drive", "v3", credentials=creds, cache_discovery=False)
    except Exception:
        raise NeedsUserAuth("User authorization required")


DRIVE_PARENT_ID = os.environ.get("DRIVE_PARENT_ID", "")


def ensure_parent_set():
    if not DRIVE_PARENT_ID:
        raise RuntimeError("DRIVE_PARENT_ID not set")


def get_or_create_team_folder(service, team: str) -> str:
    ensure_parent_set()
    # Look for exact name match under parent
    q = (
        f"name = '{team}' and mimeType = 'application/vnd.google-apps.folder' "
        f"and '{DRIVE_PARENT_ID}' in parents and trashed = false"
    )
    res = service.files().list(q=q, fields="files(id,name)", supportsAllDrives=True, includeItemsFromAllDrives=True).execute()
    files = res.get("files", [])
    if files:
        return files[0]["id"]
    folder_meta = {
        "name": team,
        "mimeType": "application/vnd.google-apps.folder",
        "parents": [DRIVE_PARENT_ID],
    }
    created = service.files().create(body=folder_meta, fields="id").execute()
    return created["id"]


def list_team_files(service, folder_id: str) -> List[Dict]:
    q = f"'{folder_id}' in parents and trashed = false"
    res = service.files().list(
        q=q,
        fields="files(id,name,mimeType,modifiedTime,size)",
        orderBy="folder,name,modifiedTime desc",
        supportsAllDrives=True,
        includeItemsFromAllDrives=True,
    ).execute()
    files = []
    for f in res.get("files", []):
        size = float(f.get("size", 0))
        modified = f.get("modifiedTime")  # RFC3339
        # Parse to datetime for template, fallback to now
        try:
            # Strip 'Z' and parse
            modified_dt = datetime.fromisoformat(modified.replace("Z", "+00:00")) if modified else datetime.utcnow()
        except Exception:
            modified_dt = datetime.utcnow()
        files.append({
            "id": f["id"],
            "name": f["name"],
            "size": size,
            "modified": modified_dt,
        })
    return files


def find_file_by_name(service, folder_id: str, name: str) -> Optional[Dict]:
    q = f"name = '{name}' and '{folder_id}' in parents and trashed = false"
    res = service.files().list(q=q, fields="files(id,name,mimeType,size)", supportsAllDrives=True, includeItemsFromAllDrives=True).execute()
    arr = res.get("files", [])
    return arr[0] if arr else None


def upload_file_to_drive(service, folder_id: str, local_path: str, original_name: str) -> str:
    # Avoid overwrite by checking if name exists, append timestamp if so
    name = original_name
    existing = find_file_by_name(service, folder_id, name)
    if existing:
        base, ext = os.path.splitext(name)
        stamp = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
        name = f"{base}_{stamp}{ext}"
    mime, _ = mimetypes.guess_type(local_path)
    media = MediaFileUpload(local_path, mimetype=mime or "application/octet-stream")
    meta = {"name": name, "parents": [folder_id]}
    created = service.files().create(body=meta, media_body=media, fields="id,name", supportsAllDrives=True).execute()
    return created["name"]


def save_final_result(service, folder_id: str, text: str) -> None:
    existing = find_file_by_name(service, folder_id, "final_result.txt")
    # Write text to a temp file and upload/update that file
    tmp = os.path.join(tempfile.gettempdir(), "final_result.txt")
    with open(tmp, "wb") as f:
        f.write(text.encode("utf-8"))
    if existing:
        service.files().update(
            fileId=existing["id"],
            media_body=MediaFileUpload(tmp, mimetype="text/plain"),
            supportsAllDrives=True,
        ).execute()
    else:
        meta = {"name": "final_result.txt", "parents": [folder_id]}
        service.files().create(
            body=meta,
            media_body=MediaFileUpload(tmp, mimetype="text/plain"),
            supportsAllDrives=True,
        ).execute()
    try:
        os.remove(tmp)
    except Exception:
        pass


def load_final_result(service, folder_id: str) -> str:
    existing = find_file_by_name(service, folder_id, "final_result.txt")
    if not existing:
        return ""
    req = service.files().get_media(fileId=existing["id"], supportsAllDrives=True) 
    fh = io.BytesIO()
    downloader = MediaIoBaseDownload(fh, req)
    done = False
    while not done:
        status, done = downloader.next_chunk()
    fh.seek(0)
    return fh.read().decode("utf-8", errors="ignore").strip()


def trash_file_by_name(service, folder_id: str, name: str) -> bool:
    if name == "final_result.txt":
        return False
    f = find_file_by_name(service, folder_id, name)
    if not f:
        return False
    # Move to trash
    service.files().update(fileId=f["id"], body={"trashed": True}, supportsAllDrives=True).execute()
    return True


@app.route("/", methods=["GET"])
def index():
    return render_template("index.html")


@app.route("/healthz")
def healthz():
    try:
        ensure_parent_set()
        service = get_drive_service()
        _maybe_clear_final_results(service)
        res = service.files().list(q=f"'{DRIVE_PARENT_ID}' in parents and trashed=false", pageSize=1, fields="files(id)").execute()
        return {"ok": True, "files_seen": len(res.get("files", []))}
    except Exception as e:
        return {"ok": False, "error": str(e)}, 500


@app.before_request
def _on_start_clear_results():
    # Best-effort clear on first handled request; guarded inside _maybe_clear_final_results
    try:
        _maybe_clear_final_results()
    except Exception:
        pass


@app.route("/authorize")
def authorize():
    try:
        client_secret_path = _write_client_secret_to_temp()
    except NeedsUserAuth as e:
        return f"Missing client secret. Set CLIENT_SECRET_JSON_B64. {e}", 400
    flow = Flow.from_client_secrets_file(
        client_secrets_file=client_secret_path,
        scopes=["https://www.googleapis.com/auth/drive"],
        redirect_uri=url_for("oauth2callback", _external=True),
    )
    authorization_url, state = flow.authorization_url(
        access_type="offline",
        include_granted_scopes="true",
        prompt="consent",
    )
    session["state"] = state
    next_url = request.args.get("next") or url_for("index")
    session["post_auth_redirect"] = next_url
    return redirect(authorization_url)


@app.route("/oauth2callback")
def oauth2callback():
    state = session.get("state")
    try:
        client_secret_path = _write_client_secret_to_temp()
    except NeedsUserAuth as e:
        return f"Missing client secret. Set CLIENT_SECRET_JSON_B64. {e}", 400
    flow = Flow.from_client_secrets_file(
        client_secrets_file=client_secret_path,
        scopes=["https://www.googleapis.com/auth/drive"],
        state=state,
        redirect_uri=url_for("oauth2callback", _external=True),
    )
    flow.fetch_token(authorization_response=request.url)
    creds = flow.credentials
    with open(TOKEN_PATH, "w") as f:
        f.write(creds.to_json())
    return redirect(session.pop("post_auth_redirect", url_for("index")))


@app.route("/login", methods=["POST"])
def login():
    team = (request.form.get("team") or "").strip().lower()
    password = (request.form.get("password") or "").strip()
    if team and TEAM_PASSWORDS.get(team) == password:
        return redirect(url_for("upload_page", team=team))
    flash("Invalid team or password", "error")
    return redirect(url_for("index"))


@app.route("/upload/<team>", methods=["GET"])
def upload_page(team):
    if team not in TEAM_PASSWORDS:
        flash("Unknown team", "error")
        return redirect(url_for("index"))
    try:
        try:
            service = get_drive_service()
        except NeedsUserAuth:
            return redirect(url_for("authorize", next=request.url))
        folder_id = get_or_create_team_folder(service, team)
        files = list_team_files(service, folder_id)
        final_result = load_final_result(service, folder_id) or ""
    except (HttpError, Exception) as e:
        files = []
        final_result = ""
        flash(f"Drive error: {e}", "error")
    return render_template("upload.html", team=team, files=files, final_result=final_result)


@app.route("/upload/<team>", methods=["POST"])
def upload_file(team):
    if team not in TEAM_PASSWORDS:
        flash("Unknown team", "error")
        return redirect(url_for("index"))

    # Save final result branch
    if "final_result_text" in request.form:
        text = (request.form.get("final_result_text") or "").strip()
        supplied = (request.form.get("final_result_password") or "").strip()
        try:
            try:
                service = get_drive_service()
            except NeedsUserAuth:
                return redirect(url_for("authorize", next=request.url))
            folder_id = get_or_create_team_folder(service, team)
            if supplied != ADMIN_PASSWORD:
                flash("Invalid admin password.", "error")
            elif len(text) > 200:
                flash("Final result too long", "error")
            else:
                save_final_result(service, folder_id, text)
                flash("Final result saved", "success")
        except (HttpError, Exception) as e:
            flash(f"Error saving final result: {e}", "error")
        return redirect(url_for("upload_page", team=team))

    if "file" not in request.files:
        flash("No file part", "error")
        return redirect(url_for("upload_page", team=team))
    file = request.files["file"]
    if file.filename == "":
        flash("No selected file", "error")
        return redirect(url_for("upload_page", team=team))
    if file and allowed_file(file.filename):
        try:
            try:
                service = get_drive_service()
            except NeedsUserAuth:
                return redirect(url_for("authorize", next=url_for("upload_page", team=team)))
            folder_id = get_or_create_team_folder(service, team)
            # Save to temp then upload
            safe_local_name = os.path.basename(file.filename)
            tmp_path = os.path.join(tempfile.gettempdir(), f"{datetime.utcnow().timestamp()}_{safe_local_name}")
            file.save(tmp_path)
            uploaded_name = upload_file_to_drive(service, folder_id, tmp_path, file.filename)
            flash(f"File uploaded as {uploaded_name}", "success")
            try:
                os.remove(tmp_path)
            except Exception:
                pass
        except HttpError as e:
            # Detect SA quota issue and trigger OAuth
            try:
                content = e.content.decode() if isinstance(e.content, (bytes, bytearray)) else str(e.content)
                data = json.loads(content) if content and content.strip().startswith("{") else {}
                reasons = [err.get("reason") for err in data.get("error", {}).get("errors", [])]
            except Exception:
                reasons = []
            msg = str(e)
            if e.resp.status == 403 and ("storageQuotaExceeded" in reasons or "Service Accounts do not have storage quota" in msg):
                flash("Service account lacks My Drive storage. Please authorize with your Google account to continue.", "error")
                return redirect(url_for("authorize", next=url_for("upload_page", team=team)))
            flash(f"Upload failed: {e}", "error")
        except Exception as e:
            flash(f"Upload failed: {e}", "error")
    else:
        flash("File type not allowed", "error")
    return redirect(url_for("upload_page", team=team))


@app.route("/download/<team>/<path:filename>")
def download_file(team, filename):
    if team not in TEAM_PASSWORDS:
        flash("Unknown team", "error")
        return redirect(url_for("index"))
    try:
        try:
            service = get_drive_service()
        except NeedsUserAuth:
            return redirect(url_for("authorize", next=request.url))
        folder_id = get_or_create_team_folder(service, team)
        f = find_file_by_name(service, folder_id, filename)
        if not f:
            flash("File not found", "error")
            return redirect(url_for("upload_page", team=team))
        req = service.files().get_media(fileId=f["id"], supportsAllDrives=True)
        fh = io.BytesIO()
        downloader = MediaIoBaseDownload(fh, req)
        done = False
        while not done:
            status, done = downloader.next_chunk()
        fh.seek(0)
        return send_file(
            fh,
            as_attachment=True,
            download_name=filename,
        )
    except (HttpError, Exception) as e:
        flash(f"Download failed: {e}", "error")
        return redirect(url_for("upload_page", team=team))


@app.route("/delete/<team>/<path:filename>", methods=["POST"])
def delete_file(team, filename):
    if team not in TEAM_PASSWORDS:
        flash("Unknown team", "error")
        return redirect(url_for("index"))
    try:
        service = get_drive_service()
        folder_id = get_or_create_team_folder(service, team)
        if filename == "final_result.txt":
            flash("Cannot delete final_result.txt", "error")
        elif trash_file_by_name(service, folder_id, filename):
            flash(f"Deleted {filename}", "success")
        else:
            flash("File not found", "error")
    except (HttpError, Exception) as e:
        flash(f"Delete failed: {e}", "error")
    return redirect(url_for("upload_page", team=team))


if __name__ == "__main__":
    # Local dev server (use gunicorn in production)
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=True)