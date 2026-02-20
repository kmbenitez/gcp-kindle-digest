# Gmail → Kindle EPUB Digest (Google Cloud)

Google Cloud Function (2nd gen) that fetches unread Gmail from the last 48 hours,
tags each email with a reference code + Gmail label, and compiles a Kindle-ready
EPUB with a seasonal public-domain cover image.

---

## Files

| File | Purpose |
|---|---|
| `main.py` | Cloud Function entry point |
| `requirements.txt` | Python dependencies |
| `deploy.sh` | Deploys to Cloud Functions via gcloud CLI |

---

## Architecture

| AWS (original) | Google Cloud (this version) |
|---|---|
| Lambda | Cloud Functions 2nd gen |
| S3 | Cloud Storage (GCS) |
| Secrets Manager | Secret Manager |
| SES (email) | SendGrid |
| IAM role | Service Account + Domain-Wide Delegation |
| CloudWatch Events | Cloud Scheduler |

### Auth — Domain-Wide Delegation (no stored tokens)

Instead of storing OAuth refresh tokens, this version uses a **Service Account with Domain-Wide Delegation**. The function assumes the identity of `GMAIL_USER` automatically at runtime — no browser login required, tokens auto-refresh.

---

## Setup (one-time)

### 1. Enable APIs

```bash
gcloud services enable \
  gmail.googleapis.com \
  cloudfunctions.googleapis.com \
  cloudscheduler.googleapis.com \
  secretmanager.googleapis.com \
  storage.googleapis.com
```

### 2. Create a Service Account

```bash
gcloud iam service-accounts create digest-bot \
  --display-name="Kindle Digest Bot" \
  --project=YOUR_PROJECT_ID
```

### 3. Grant Domain-Wide Delegation

1. Go to **Google Workspace Admin Console** → Security → API Controls → Domain-wide Delegation
2. Click **Add new** and enter:
   - **Client ID**: the service account's OAuth2 client ID (find it at IAM → Service Accounts → your SA → Details)
   - **Scopes**: `https://www.googleapis.com/auth/gmail.modify`
3. Save

### 4. Grant Service Account Permissions

```bash
PROJECT_ID=your-project-id
SA=digest-bot@${PROJECT_ID}.iam.gserviceaccount.com

# Cloud Storage
gsutil mb gs://my-kindle-digest-bucket
gsutil iam ch serviceAccount:${SA}:objectCreator gs://my-kindle-digest-bucket

# Secret Manager (read-only)
gcloud projects add-iam-policy-binding $PROJECT_ID \
  --member="serviceAccount:${SA}" \
  --role="roles/secretmanager.secretAccessor"
```

### 5. Store SendGrid API Key

```bash
echo -n "YOUR_SENDGRID_API_KEY" | \
  gcloud secrets create sendgrid-api-key --data-file=-
```

### 6. Deploy

```bash
export GCP_PROJECT_ID=your-project-id
export GMAIL_USER=you@yourdomain.com
export GCS_BUCKET=my-kindle-digest-bucket
export KINDLE_EMAIL=yourname_abc123@kindle.com   # optional
export SENDER_EMAIL=you@yourdomain.com           # verified SendGrid sender

chmod +x deploy.sh
./deploy.sh
```

---

## Environment Variables

| Variable | Required | Example |
|---|---|---|
| `GCP_PROJECT_ID` | Yes | `my-project-123` |
| `DIGEST_GCS_BUCKET` | Yes | `my-kindle-digest-bucket` |
| `DIGEST_GCS_PREFIX` | No | `digests/` |
| `GMAIL_USER` | Yes | `you@yourdomain.com` |
| `KINDLE_EMAIL` | No | `yourname@kindle.com` |
| `SENDER_EMAIL` | No | `you@yourdomain.com` |
| `SENDGRID_SECRET_NAME` | No | `sendgrid-api-key` |

---

## Scheduling with Cloud Scheduler

```bash
gcloud scheduler jobs create http daily-digest \
  --location=us-central1 \
  --schedule="0 7 * * *" \
  --uri="https://REGION-PROJECT_ID.cloudfunctions.net/gmail-kindle-digest" \
  --oidc-service-account-email="digest-bot@PROJECT_ID.iam.gserviceaccount.com" \
  --message-body="{}"
```

This runs at 7:00 AM UTC daily. Adjust the cron expression as needed.

---

## Finding Emails from a Digest

Each email gets two reference handles:

1. **Gmail label** — every email in a run is tagged `KindleDigest/2026-02-19_0700`.
   Search Gmail: `label:KindleDigest/2026-02-19_0700`

2. **REF code** — each chapter header shows `REF:A3F9B2`.
   This is a stable 6-char hash of the Gmail message ID.

---

## Customising Exclusions

Edit the `EXCLUSIONS` list in `main.py`:

```python
EXCLUSIONS = [
    {"domain": "marketing.example.com"},
    {"sender": "noreply@service.com"},
    {"subject_contains": "weekly recap"},
]
```
