"""
Gmail → EPUB Kindle Digest
Google Cloud Function (2nd gen) — HTTP trigger

Fetches unread Gmail from the last 48 hours, tags each email with a
reference code + Gmail label, compiles a Kindle-ready EPUB with a
seasonal public-domain cover image, uploads to Cloud Storage, and
optionally sends to a Kindle delivery address via SendGrid.

Auth strategy:
  The Cloud Function runs as a dedicated Service Account that has been
  granted Gmail access via Google Workspace Domain-Wide Delegation.
  No OAuth tokens need to be stored or refreshed manually.
"""

import os
import io
import json
import base64
import hashlib
import logging
import re
import urllib.request
import urllib.parse
import random
from datetime import datetime, timezone, timedelta
from email.header import decode_header
from email.utils import parsedate_to_datetime
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email.mime.text import MIMEText
from email import encoders

import functions_framework
from google.oauth2 import service_account
from google.auth import default as google_auth_default
from google.auth.transport.requests import Request as GoogleAuthRequest
from googleapiclient.discovery import build
from google.cloud import storage, secretmanager
from ebooklib import epub
import sendgrid
from sendgrid.helpers.mail import Mail, Attachment, FileContent, FileName, FileType, Disposition

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# EXCLUSION LIST
# Edit this list to suppress senders, domains, or subject patterns.
# Each entry is a dict with ONE of: "sender", "domain", "subject_contains"
# ---------------------------------------------------------------------------
EXCLUSIONS = [
    {"domain": "noreply.github.com"},
    {"domain": "notifications.google.com"},
    {"domain": "mail.notion.so"},
    {"sender": "no-reply@accounts.google.com"},
    {"subject_contains": "unsubscribe"},
    {"subject_contains": "[SPAM]"},
    {"subject_contains": "newsletter"},          # remove if you WANT newsletters
    # Add more as needed:
    # {"domain": "marketing.example.com"},
    # {"sender": "alerts@example.com"},
    # {"subject_contains": "digest"},
]

# Gmail label applied to every email included in a digest run
DIGEST_LABEL_PREFIX = "KindleDigest"

# GCP project and resources (set as Cloud Function environment variables)
GCP_PROJECT_ID       = os.environ.get("GCP_PROJECT_ID", "")
GCS_BUCKET           = os.environ.get("DIGEST_GCS_BUCKET", "my-kindle-digest-bucket")
GCS_PREFIX           = os.environ.get("DIGEST_GCS_PREFIX", "digests/")

# Gmail impersonation: the Google Workspace user whose inbox to read
GMAIL_USER           = os.environ.get("GMAIL_USER", "")          # e.g. "you@yourdomain.com"

# Kindle delivery
KINDLE_EMAIL         = os.environ.get("KINDLE_EMAIL", "")        # e.g. "yourname@kindle.com"
SENDER_EMAIL         = os.environ.get("SENDER_EMAIL", "")        # verified SendGrid sender

# SendGrid API key — stored in GCP Secret Manager
SENDGRID_SECRET_NAME = os.environ.get("SENDGRID_SECRET_NAME", "sendgrid-api-key")


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------

def get_gmail_service():
    """
    Build a Gmail API client using Application Default Credentials with
    domain-wide delegation to impersonate GMAIL_USER.

    The Cloud Function's service account must be:
      1. Granted domain-wide delegation in Google Workspace Admin Console
      2. Authorised for scope: https://www.googleapis.com/auth/gmail.modify
    """
    scopes = ["https://www.googleapis.com/auth/gmail.modify"]

    credentials, _ = google_auth_default(scopes=scopes)

    # Delegate to the target inbox
    if GMAIL_USER:
        credentials = credentials.with_subject(GMAIL_USER)

    return build("gmail", "v1", credentials=credentials)


def get_sendgrid_key() -> str:
    """Fetch the SendGrid API key from GCP Secret Manager."""
    client = secretmanager.SecretManagerServiceClient()
    name = f"projects/{GCP_PROJECT_ID}/secrets/{SENDGRID_SECRET_NAME}/versions/latest"
    response = client.access_secret_version(request={"name": name})
    return response.payload.data.decode("utf-8").strip()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_ref_id(msg_id: str) -> str:
    """Short 6-char alphanumeric reference code derived from the Gmail message ID."""
    return hashlib.sha256(msg_id.encode()).hexdigest()[:6].upper()


def is_excluded(sender: str, subject: str) -> bool:
    """Return True if the email matches any exclusion rule."""
    sender_lower = sender.lower()
    subject_lower = subject.lower()

    for rule in EXCLUSIONS:
        if "sender" in rule and rule["sender"].lower() in sender_lower:
            return True
        if "domain" in rule:
            domain = rule["domain"].lower()
            if f"@{domain}" in sender_lower or f".{domain}" in sender_lower:
                return True
        if "subject_contains" in rule and rule["subject_contains"].lower() in subject_lower:
            return True

    return False


def decode_mime_header(value: str) -> str:
    """Decode RFC-2047 encoded email headers."""
    parts = decode_header(value or "")
    decoded = []
    for part, enc in parts:
        if isinstance(part, bytes):
            decoded.append(part.decode(enc or "utf-8", errors="replace"))
        else:
            decoded.append(part)
    return "".join(decoded)


def abbreviate_title(subject: str, sender: str, date: datetime) -> str:
    """
    Create a chapter title from subject + sender + date.
    Format: "SubjectSnippet | Sender | MMM-DD"
    """
    subj = re.sub(r"\s+", " ", subject).strip()
    subj = subj[:40] + "…" if len(subj) > 40 else subj

    name_match = re.match(r"^([^<]+)<", sender)
    if name_match:
        sender_short = name_match.group(1).strip()[:20]
    else:
        local = re.sub(r"@.*", "", sender)
        sender_short = local[:20]

    date_str = date.strftime("%b-%d")
    return f"{subj} | {sender_short} | {date_str}"


def get_email_body(payload: dict) -> tuple[str, list[dict]]:
    """
    Recursively extract the HTML (preferred) or plain-text body,
    and collect inline image attachments.
    Returns (html_body, [{"cid": ..., "data": bytes, "mime": ...}])
    """
    html_body = ""
    text_body = ""
    images = []

    def walk(part):
        nonlocal html_body, text_body
        mime = part.get("mimeType", "")
        body_data = part.get("body", {})
        parts = part.get("parts", [])

        if mime == "text/html" and body_data.get("data"):
            html_body += base64.urlsafe_b64decode(body_data["data"]).decode("utf-8", errors="replace")
        elif mime == "text/plain" and body_data.get("data"):
            text_body += base64.urlsafe_b64decode(body_data["data"]).decode("utf-8", errors="replace")
        elif mime.startswith("image/") and body_data.get("data"):
            cid = None
            for header in part.get("headers", []):
                if header["name"].lower() == "content-id":
                    cid = header["value"].strip("<>")
            images.append({
                "cid": cid or f"img_{len(images)}",
                "data": base64.urlsafe_b64decode(body_data["data"]),
                "mime": mime,
            })

        for p in parts:
            walk(p)

    walk(payload)

    body = html_body if html_body else f"<pre>{text_body}</pre>"
    return body, images


# ---------------------------------------------------------------------------
# Email fetching
# ---------------------------------------------------------------------------

def fetch_emails(service) -> list[dict]:
    """Fetch unread emails from the last 48 hours, excluding filtered senders."""
    since = (datetime.now(timezone.utc) - timedelta(hours=48)).strftime("%Y/%m/%d")
    query = f"is:unread after:{since}"

    result = service.users().messages().list(userId="me", q=query, maxResults=100).execute()
    message_refs = result.get("messages", [])

    emails = []
    for ref in message_refs:
        msg = service.users().messages().get(
            userId="me", id=ref["id"], format="full"
        ).execute()

        headers = {h["name"].lower(): h["value"] for h in msg["payload"].get("headers", [])}
        subject = decode_mime_header(headers.get("subject", "(No Subject)"))
        sender  = decode_mime_header(headers.get("from", "unknown@unknown.com"))
        date_str = headers.get("date", "")

        try:
            email_date = parsedate_to_datetime(date_str)
        except Exception:
            email_date = datetime.now(timezone.utc)

        if is_excluded(sender, subject):
            logger.info(f"Excluded: {sender} | {subject}")
            continue

        body, images = get_email_body(msg["payload"])
        ref_id = make_ref_id(msg["id"])

        emails.append({
            "id": msg["id"],
            "ref_id": ref_id,
            "subject": subject,
            "sender": sender,
            "date": email_date,
            "body": body,
            "images": images,
            "chapter_title": abbreviate_title(subject, sender, email_date),
        })

    emails.sort(key=lambda e: e["date"])
    return emails


def tag_emails(service, emails: list[dict], label_name: str):
    """Create a digest label (if needed) and apply it to all included emails."""
    existing = service.users().labels().list(userId="me").execute().get("labels", [])
    label_id = next((l["id"] for l in existing if l["name"] == label_name), None)

    if not label_id:
        new_label = service.users().labels().create(
            userId="me",
            body={
                "name": label_name,
                "labelListVisibility": "labelShow",
                "messageListVisibility": "show",
            },
        ).execute()
        label_id = new_label["id"]

    for email in emails:
        service.users().messages().modify(
            userId="me",
            id=email["id"],
            body={"addLabelIds": [label_id]},
        ).execute()

    logger.info(f"Tagged {len(emails)} emails with label '{label_name}'")


# ---------------------------------------------------------------------------
# Seasonal cover image (Wikimedia Commons — public domain)
# ---------------------------------------------------------------------------

SEASON_SEARCH_TERMS = {
    "spring": [
        "spring cherry blossom painting",
        "spring meadow flowers botanical illustration",
        "April showers watercolor art",
        "spring birds nest vintage illustration",
        "tulip field painting public domain",
    ],
    "summer": [
        "summer landscape painting impressionist",
        "sunflower field oil painting",
        "beach sunset vintage painting",
        "summer harvest wheat field painting",
        "lavender field watercolor illustration",
    ],
    "autumn": [
        "autumn fall foliage painting",
        "harvest pumpkin vintage illustration",
        "October forest landscape painting",
        "autumn leaves watercolor art",
        "apple harvest vintage botanical print",
    ],
    "winter": [
        "winter snow landscape painting",
        "Christmas winter village vintage illustration",
        "January frost botanical illustration",
        "winter forest snow oil painting",
        "snowy mountain landscape painting public domain",
    ],
}


def get_season(date: datetime) -> str:
    month = date.month
    if month in (3, 4, 5):   return "spring"
    elif month in (6, 7, 8): return "summer"
    elif month in (9, 10, 11): return "autumn"
    else:                     return "winter"


def fetch_cover_image(run_date: datetime) -> tuple[bytes, str, str] | tuple[None, None, None]:
    """
    Search Wikimedia Commons for a seasonal public-domain image.
    Returns (image_bytes, mime_type, image_title) or (None, None, None) on failure.
    """
    season = get_season(run_date)
    search_term = random.choice(SEASON_SEARCH_TERMS[season])
    logger.info(f"Season: {season} | Cover image search: '{search_term}'")

    search_url = (
        "https://commons.wikimedia.org/w/api.php?"
        + urllib.parse.urlencode({
            "action": "query",
            "list": "search",
            "srsearch": search_term,
            "srnamespace": 6,
            "srlimit": 20,
            "srwhat": "text",
            "format": "json",
        })
    )

    try:
        req = urllib.request.Request(search_url, headers={"User-Agent": "KindleDigestBot/1.0"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            search_data = json.loads(resp.read().decode())
    except Exception as e:
        logger.warning(f"Wikimedia search failed: {e}")
        return None, None, None

    results = search_data.get("query", {}).get("search", [])
    if not results:
        return None, None, None

    random.shuffle(results)

    for result in results[:8]:
        title = result["title"]

        info_url = (
            "https://commons.wikimedia.org/w/api.php?"
            + urllib.parse.urlencode({
                "action": "query",
                "titles": title,
                "prop": "imageinfo",
                "iiprop": "url|mime|extmetadata",
                "iiurlwidth": 1200,
                "format": "json",
            })
        )

        try:
            req = urllib.request.Request(info_url, headers={"User-Agent": "KindleDigestBot/1.0"})
            with urllib.request.urlopen(req, timeout=10) as resp:
                info_data = json.loads(resp.read().decode())
        except Exception as e:
            logger.warning(f"Could not fetch image info for {title}: {e}")
            continue

        pages = info_data.get("query", {}).get("pages", {})
        page = next(iter(pages.values()))
        imageinfo = page.get("imageinfo", [{}])[0]

        mime = imageinfo.get("mime", "")
        if mime not in ("image/jpeg", "image/png"):
            continue

        extmeta = imageinfo.get("extmetadata", {})
        license_short = extmeta.get("LicenseShortName", {}).get("value", "")
        license_url   = extmeta.get("LicenseUrl", {}).get("value", "")

        free_licenses = ("cc0", "public domain", "pd", "cc-by", "cc by")
        is_free = any(t in license_short.lower() for t in free_licenses) or \
                  any(t in license_url.lower() for t in ("cc0", "publicdomain"))

        if not is_free:
            logger.info(f"Skipping non-free image: {title} ({license_short})")
            continue

        image_url = imageinfo.get("thumburl") or imageinfo.get("url")
        if not image_url:
            continue

        try:
            req = urllib.request.Request(image_url, headers={"User-Agent": "KindleDigestBot/1.0"})
            with urllib.request.urlopen(req, timeout=15) as resp:
                image_bytes = resp.read()
            display_title = title.replace("File:", "").rsplit(".", 1)[0]
            logger.info(f"Cover image: {display_title} ({license_short})")
            return image_bytes, mime, display_title
        except Exception as e:
            logger.warning(f"Failed to download image {image_url}: {e}")
            continue

    logger.warning("No suitable public-domain cover image found.")
    return None, None, None


# ---------------------------------------------------------------------------
# EPUB builder
# ---------------------------------------------------------------------------

def build_epub(emails: list[dict], run_label: str, run_date: datetime) -> bytes:
    """Compile emails into a Kindle-ready EPUB file."""
    book = epub.EpubBook()
    book.set_identifier(f"digest-{run_date.strftime('%Y%m%d%H%M%S')}")
    book.set_title(f"Email Digest — {run_date.strftime('%B %d, %Y')}")
    book.set_language("en")
    book.add_author("Gmail Digest Bot")

    style = epub.EpubItem(
        uid="style",
        file_name="style/digest.css",
        media_type="text/css",
        content="""
body { font-family: Georgia, serif; font-size: 1em; line-height: 1.6; margin: 1em; }
h1 { font-size: 1.3em; border-bottom: 1px solid #ccc; padding-bottom: 0.3em; }
h2 { font-size: 1.1em; color: #444; }
.meta { font-size: 0.85em; color: #666; margin-bottom: 1em; }
.ref-tag { background: #f0f0f0; border: 1px solid #ccc; padding: 2px 6px;
           font-family: monospace; font-size: 0.9em; border-radius: 3px; }
.email-body { margin-top: 1em; }
img { max-width: 100%; height: auto; }
hr { border: none; border-top: 1px solid #ddd; margin: 2em 0; }
.cover-image-wrap { text-align: center; margin-bottom: 1.5em; }
.cover-image-wrap img { max-height: 400px; width: auto; max-width: 100%; border: 1px solid #ddd; }
.cover-caption { font-size: 0.7em; color: #999; font-style: italic; margin-top: 0.3em; }
""",
    )
    book.add_item(style)

    # Seasonal cover image
    season = get_season(run_date)
    cover_img_bytes, cover_mime, cover_title = fetch_cover_image(run_date)

    cover_img_tag = ""
    cover_caption = ""
    if cover_img_bytes and cover_mime:
        ext = "jpg" if cover_mime == "image/jpeg" else "png"
        cover_img_item = epub.EpubItem(
            uid="cover_image",
            file_name=f"images/cover.{ext}",
            media_type=cover_mime,
            content=cover_img_bytes,
        )
        book.add_item(cover_img_item)
        book.set_cover(f"images/cover.{ext}", cover_img_bytes)
        cover_img_tag = f'<img src="images/cover.{ext}" alt="Seasonal cover" style="max-width:100%;"/>'
        cover_caption = f'<p class="cover-caption">{cover_title} · Public Domain / Wikimedia Commons</p>'

    chapters = []
    toc = []

    cover_html = f"""<?xml version='1.0' encoding='utf-8'?>
<!DOCTYPE html>
<html xmlns="http://www.w3.org/1999/xhtml">
<head><title>Email Digest</title>
<link rel="stylesheet" href="style/digest.css" /></head>
<body>
<div class="cover-image-wrap">
{cover_img_tag}
{cover_caption}
</div>
<h1>Email Digest</h1>
<p class="meta">{run_date.strftime('%A, %B %d, %Y at %H:%M UTC')} · {season.capitalize()}</p>
<p><strong>{len(emails)}</strong> emails collected</p>
<p>Gmail label: <span class="ref-tag">{run_label}</span></p>
<hr/>
<p>Each chapter header contains a <span class="ref-tag">REF:XXXXXX</span> code.
Search Gmail for <code>label:{run_label}</code> to view all emails in this digest.</p>
</body></html>"""

    cover_chapter = epub.EpubHtml(title="Digest Cover", file_name="cover.xhtml", lang="en")
    cover_chapter.content = cover_html
    cover_chapter.add_item(style)
    book.add_item(cover_chapter)
    chapters.append(cover_chapter)
    toc.append(cover_chapter)

    for i, email in enumerate(emails, 1):
        img_items = {}
        for img in email["images"]:
            ext = img["mime"].split("/")[-1]
            img_filename = f"images/img_{i}_{img['cid'].replace('@', '_')}.{ext}"
            epub_img = epub.EpubItem(
                uid=f"img_{i}_{img['cid']}",
                file_name=img_filename,
                media_type=img["mime"],
                content=img["data"],
            )
            book.add_item(epub_img)
            img_items[img["cid"]] = img_filename

        body_html = email["body"]
        for cid, path in img_items.items():
            body_html = body_html.replace(f"cid:{cid}", path)

        ref_id = email["ref_id"]
        chapter_html = f"""<?xml version='1.0' encoding='utf-8'?>
<!DOCTYPE html>
<html xmlns="http://www.w3.org/1999/xhtml">
<head><title>{email['chapter_title']}</title>
<link rel="stylesheet" href="style/digest.css" /></head>
<body>
<h1>{email['chapter_title']}</h1>
<div class="meta">
  <strong>From:</strong> {email['sender']}<br/>
  <strong>Date:</strong> {email['date'].strftime('%B %d, %Y %H:%M UTC')}<br/>
  <strong>Subject:</strong> {email['subject']}<br/>
  <strong>Reference:</strong> <span class="ref-tag">REF:{ref_id}</span>
  &nbsp;·&nbsp; Gmail label: <span class="ref-tag">{run_label}</span>
</div>
<hr/>
<div class="email-body">
{body_html}
</div>
</body></html>"""

        ch = epub.EpubHtml(
            title=email["chapter_title"],
            file_name=f"email_{i:03d}_{ref_id}.xhtml",
            lang="en",
        )
        ch.content = chapter_html
        ch.add_item(style)
        book.add_item(ch)
        chapters.append(ch)
        toc.append(ch)

    book.toc = toc
    book.spine = ["nav"] + chapters
    book.add_item(epub.EpubNcx())
    book.add_item(epub.EpubNav())

    buf = io.BytesIO()
    epub.write_epub(buf, book, {})
    return buf.getvalue()


# ---------------------------------------------------------------------------
# Cloud Storage upload
# ---------------------------------------------------------------------------

def upload_to_gcs(epub_bytes: bytes, blob_name: str) -> str:
    """Upload EPUB to Google Cloud Storage and return the GCS URI."""
    client = storage.Client()
    bucket = client.bucket(GCS_BUCKET)
    blob = bucket.blob(blob_name)
    blob.upload_from_string(epub_bytes, content_type="application/epub+zip")
    uri = f"gs://{GCS_BUCKET}/{blob_name}"
    logger.info(f"Uploaded EPUB to {uri}")
    return uri


# ---------------------------------------------------------------------------
# Kindle delivery via SendGrid
# ---------------------------------------------------------------------------

def send_to_kindle(epub_bytes: bytes, filename: str):
    """Email the EPUB to a Kindle delivery address via SendGrid."""
    if not KINDLE_EMAIL or not SENDER_EMAIL:
        logger.info("KINDLE_EMAIL or SENDER_EMAIL not set — skipping Kindle delivery.")
        return

    try:
        api_key = get_sendgrid_key()
    except Exception as e:
        logger.warning(f"Could not retrieve SendGrid key: {e}")
        return

    encoded = base64.b64encode(epub_bytes).decode()

    message = Mail(
        from_email=SENDER_EMAIL,
        to_emails=KINDLE_EMAIL,
        subject="convert",          # Kindle "Convert" command
        plain_text_content="Your email digest is attached.",
    )

    attachment = Attachment(
        file_content=FileContent(encoded),
        file_name=FileName(filename),
        file_type=FileType("application/epub+zip"),
        disposition=Disposition("attachment"),
    )
    message.attachment = attachment

    sg = sendgrid.SendGridAPIClient(api_key=api_key)
    response = sg.send(message)
    logger.info(f"Sent EPUB to Kindle ({KINDLE_EMAIL}): HTTP {response.status_code}")


# ---------------------------------------------------------------------------
# Cloud Function entry point (HTTP trigger)
# ---------------------------------------------------------------------------

@functions_framework.http
def digest(request):
    """
    HTTP-triggered Cloud Function.
    Invoke manually or via Cloud Scheduler with any POST/GET request.
    """
    run_date  = datetime.now(timezone.utc)
    run_label = f"{DIGEST_LABEL_PREFIX}/{run_date.strftime('%Y-%m-%d_%H%M')}"

    logger.info(f"Starting digest run: {run_label}")

    service = get_gmail_service()
    emails  = fetch_emails(service)
    logger.info(f"Fetched {len(emails)} emails after exclusions")

    if not emails:
        return ("No emails to digest.", 200)

    tag_emails(service, emails, run_label)

    epub_bytes    = build_epub(emails, run_label, run_date)
    epub_filename = f"digest_{run_date.strftime('%Y%m%d_%H%M')}.epub"
    gcs_uri       = upload_to_gcs(epub_bytes, f"{GCS_PREFIX}{epub_filename}")

    send_to_kindle(epub_bytes, epub_filename)

    result = {
        "emails_included": len(emails),
        "gmail_label":     run_label,
        "epub_gcs_uri":    gcs_uri,
        "epub_filename":   epub_filename,
    }
    return (json.dumps(result), 200, {"Content-Type": "application/json"})
