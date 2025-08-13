# AWA 2025 Team File Upload Web App

Simple Flask application allowing 4 teams to upload and download files with individual passwords. App was coded by prompting chatgpt 5.0

## Features
- Team selection with per-team password (hard-coded for demo)
- File upload with size limit and allowed extensions
- Auto-creates separate folder per team under `app/uploads/<team>`
- Prevents overwriting by timestamping duplicate names
- Lists uploaded files with size & last modified timestamp
- Download links for each file

## Quick Start

### 1. Create & Activate Virtual Environment (Windows PowerShell)
```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
```

### 2. Install Dependencies
```powershell
pip install -r requirements.txt
```

### 3. Run App
```powershell
python app/app.py
```

### 4. Open in Browser
Navigate to: http://127.0.0.1:5000/

## Team Passwords
- team1 / pw1
- team2 / pw2
- team3 / pw3
- team4 / pw4

## Environment Variables (Optional)
You can override the secret key:
```powershell
$env:FLASK_SECRET="a-better-secret"
```
Then modify `app.py` to read from environment if desired.

## Notes / Next Steps
- Replace hard-coded passwords with hashed values in a datastore for production.
- Add authentication session to avoid URL-guessing (currently minimal security).
- Add deletion functionality with confirmation if required.
- Add progress bar or multiple-file upload.

---

## Deploy the Shiny (service account) app to Google Cloud Run

There’s a Shiny variant under `shiny_app/` that persists files to Google Drive using a service account. A Dockerfile is provided to deploy it on Cloud Run.

### Prerequisites
- gcloud CLI installed and authenticated
- Cloud Run and Artifact Registry enabled in your project
- A service account with Drive access (Editor on the target Drive folder) and permission to run Cloud Run
- The Drive parent folder shared with the service account email

### Configure auth
The app tries service account JSON first, then Application Default Credentials (ADC) if running on Cloud Run:
- Option A (ADC recommended): Deploy with a Cloud Run service account that has Drive access; no key needed.
- Option B (JSON key): Base64-encode the key and pass it as `SERVICE_ACCOUNT_JSON_B64`, or paste into `SERVICE_ACCOUNT_JSON_B64_CONSTANT` in `shiny_app/app_service_account.R`.

Always set `DRIVE_PARENT_ID` to the Google Drive folder ID (from the folder URL) that contains team subfolders.

### Build and deploy (from `shiny_app/`)
```powershell
$PROJECT = "your-gcp-project"
$REGION  = "australia-southeast1"
$REPO    = "awa-shiny"
$IMAGE   = "shiny-app"

# One-time: create Artifact Registry repo
gcloud artifacts repositories create $REPO --repository-format=docker --location=$REGION --description="AWA Shiny"

# Build container and push
gcloud builds submit --tag "$REGION-docker.pkg.dev/$PROJECT/$REPO/$IMAGE:latest" .

# Deploy to Cloud Run (replace SERVICE_ACCOUNT with your SA email)
gcloud run deploy awa-shiny `
	--image="$REGION-docker.pkg.dev/$PROJECT/$REPO/$IMAGE:latest" `
	--region=$REGION `
	--platform=managed `
	--allow-unauthenticated `
	--service-account=SERVICE_ACCOUNT `
	--set-env-vars=DRIVE_PARENT_ID=YOUR_FOLDER_ID
```

If using the JSON key instead of ADC, add:
```powershell
--set-env-vars=SERVICE_ACCOUNT_JSON_B64="<base64-contents>"
```

### Share the Drive folder
Share the parent folder (or Shared Drive) with the service account as Editor/Content manager, and use that folder’s ID for `DRIVE_PARENT_ID`.

### Verify
Open the Cloud Run URL, log in as a team, upload a small test file, and save the Final Result using the admin password (default `admin` unless overridden).

Troubleshooting:
- 403/404 from Drive: Folder not shared with the service account, wrong folder ID, or role too low.
- Auth failure modal: Provide `SERVICE_ACCOUNT_JSON_B64` or run with ADC on Cloud Run.

### Upload size limits
- Local Flask (filesystem) and Drive-backed Flask now allow up to 500 MB per request via `MAX_CONTENT_LENGTH`.
- Shiny service-account app allows up to 500 MB via `options(shiny.maxRequestSize)`.
- Cloud Run note: HTTP request body to a single instance is effectively limited by proxies (commonly ~32 MiB). For uploads >32 MiB on Cloud Run, consider:
	- Using a direct, signed upload to Cloud Storage from the browser, then a backend job moves the file to Drive.
	- Using resumable uploads (chunked) to Cloud Storage; process asynchronously.
	- Hosting behind a service that supports larger payloads (e.g., Cloud Run with a reverse proxy that streams to GCS).
