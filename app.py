"""
IDkat: find and fix your personal information online. Free, supported by sponsors.

- Free accounts with a username and password. Reports are kept in each user's library,
  encrypted with a key only they hold: the administrator can see usernames and usage,
  never
  names, searches, answers or reports.

- Sign in with your email: no password. A one-time link is emailed to you with the
consent notice.
- IDkat searches the public web for information about YOU: social media, forums, blogs,
  people-search sites and other listings.
- Results show WHERE information is exposed and HOW to remove it, never the details
themselves.
- Your two reports (a one-page summary and a full action plan) are emailed to you, then
every
  result is deleted. Nothing is written to disk.
"""

import datetime
import os
import hashlib
import hmac
import html
import io
import json
import re
import secrets as pysecrets
import smtplib
import ssl
import threading
import time
import uuid
from base64 import b64encode, urlsafe_b64decode, urlsafe_b64encode
from email.message import EmailMessage
from pathlib import Path
from urllib.parse import urlparse
from zoneinfo import ZoneInfo

import bcrypt
import matplotlib
import pandas as pd
import requests
import streamlit as st
from fpdf import FPDF
from google import genai
from google.genai import types
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from pydantic import BaseModel, Field
from sqlalchemy import create_engine
from sqlalchemy import text as sql_text

st.set_page_config(page_title="IDkat", page_icon="🐾", layout="centered")

# ============================================================================
# 0. SETTINGS
# ============================================================================
DEFAULT_MODEL = "gemini-3.8-flash"
FALLBACK_MODEL = "gemini-flash-latest"
LINK_MINUTES = 15  # sign-in links expire after this
SESSION_HOURS = 2  # staying signed in after a refresh
RESULTS_HOURS = 2  # results are deleted after this if not emailed first
NAME_LOCK_DAYS = 30  # one name per email address for this long
MAX_LINKS_PER_HOUR = 3
MAX_SCANS_PER_DAY = 2
INK, BONE, SAND, MUTED = (
    "#14120F",
    "#F2EDE3",
    "#C6BCA9",
    "#5E574C",
)  # MUTED: readable grey on white

CHANNELS = {
    "Social media": "public profiles, posts, photos and comments on Facebook, "
    "Instagram, X, LinkedIn, "
    "TikTok, YouTube, Threads, Pinterest and similar",
    "Forums and communities": "Reddit, Whirlpool, Quora, Stack Exchange, community "
    "forums and comment sections",
    "Blogs and personal sites": "blogs, personal websites, Medium, Substack and "
    "WordPress, including mentions "
    "in other people's posts",
    "People-search sites and data brokers": "people-search sites, data brokers, "
    "directories and lookup sites "
    "that list names with addresses, phone numbers, relatives or ages",
    "Other public listings": "business and association registers, club, school and "
    "event pages, review "
    "sites, old CVs and other pages that mention the person",
}
EXPOSED_TYPES = [
    "Home address",
    "Phone number",
    "Email address",
    "Date of birth or age",
    "Photos",
    "Workplace",
    "Relatives or associates",
    "Usernames",
    "Location or city",
    "Financial details",
    "ID numbers",
    "Children's details",
    "Health information",
    "Posts or opinions",
    "Other",
]
HIGH_TYPES = {
    "Home address",
    "Phone number",
    "Date of birth or age",
    "Financial details",
    "ID numbers",
    "Children's details",
    "Health information",
}
MATCHES = ("Likely you", "Possibly you", "Probably someone else")
EFFORTS = ("Quick", "Moderate", "Hard")
PAGE_TYPES = [
    "Social profile",
    "Social post",
    "Forum post",
    "Blog or article",
    "People-search or data broker",
    "Directory or listing",
    "Other",
]

GENERAL_ADVICE = [
    (
        "Ask Google to remove results",
        "Google's 'Results about you' tool (in your Google account) lets you "
        "request removal of search results showing your phone number, home address or "
        "email address.",
    ),
    (
        "Opt out of people-search sites",
        "Most people-search and data-broker sites have an opt-out or removal "
        "page, often in the site footer. Removal requests may take several weeks, and "
        "some sites re-list "
        "people later, so check again every few months.",
    ),
    (
        "Tighten your social media settings",
        "Set profiles to private or friends-only, hide your friends list, "
        "turn off being found by phone number or email, and remove location details "
        "from old posts.",
    ),
    (
        "Close old accounts",
        "Delete accounts you no longer use, especially old forums and blogs. Deleting "
        "is "
        "better than abandoning, because old accounts are often the source of leaked "
        "details.",
    ),
    (
        "Ask site owners directly",
        "For blogs, forums and listings, contact the site owner or moderators and "
        "ask for your details to be removed. Keep a record of what you asked and when.",
    ),
    (
        "Protect yourself after data breaches",
        "If your email appears in a data breach, change that password "
        "and any others like it, and turn on multi-factor authentication.",
    ),
    (
        "Get help if you're being targeted",
        "In Australia, eSafety can help with serious online abuse and "
        "image-based abuse, and the OAIC handles privacy complaints about businesses. "
        "If you feel unsafe, "
        "contact the police.",
    ),
]


_SECRET_CACHE = {}
SECRET_NAMES = (
    "KATADMIN_PASSWORD_HASH",
    "TIMEZONE",
    "IDKAT_SECRET",
    "APP_URL",
    "GEMINI_API_KEY",
    "GEMINI_MODEL",
    "SMTP_HOST",
    "SMTP_PORT",
    "SMTP_USER",
    "SMTP_PASSWORD",
    "SMTP_FROM",
    "HIBP_API_KEY",
    "DAILY_SCAN_CAP",
)


def secret(name, default=None):
    """Reads a setting. Background searches can't always read Secrets directly, so the
    page
    keeps a copy for them."""
    try:
        value = st.secrets[name]
        _SECRET_CACHE[name] = value
        return value
    except Exception:
        return _SECRET_CACHE.get(name, default)


for _name in SECRET_NAMES:
    secret(_name)


def app_secret():
    value = str(secret("IDKAT_SECRET", "") or "")
    return value.encode() if len(value) >= 32 else b""


# ============================================================================
# 1. MEMORY-ONLY STORE (nothing is written to disk)
# ============================================================================
@st.cache_resource
def _store():
    return {
        "lock": threading.Lock(),
        "used_links": {},
        "link_requests": {},
        "scans": {},
        "names": {},
        "jobs": {},
        "daily_total": {},
    }


STORE = _store()


def fingerprint(value):
    """A scrambled, one-way fingerprint so limits can be enforced without keeping emails or names."""
    return hmac.new(
        app_secret() or b"idkat", str(value).strip().lower().encode(), "sha256"
    ).hexdigest()[:24]


def purge_expired():
    now = time.time()
    with STORE["lock"]:
        for job_id in [
            j
            for j, job in STORE["jobs"].items()
            if now - job["started"] > RESULTS_HOURS * 3600
        ]:
            del STORE["jobs"][job_id]
        for key in [k for k, until in STORE["used_links"].items() if until < now]:
            del STORE["used_links"][key]
        for key in [k for k, v in STORE["names"].items() if v["until"] < now]:
            del STORE["names"][key]
        for bucket in ("link_requests", "scans"):
            for key in list(STORE[bucket]):
                STORE[bucket][key] = [t for t in STORE[bucket][key] if now - t < 86400]


def within_limit(bucket, key, limit, seconds):
    now = time.time()
    with STORE["lock"]:
        recent = [t for t in STORE[bucket].get(key, []) if now - t < seconds]
        if len(recent) >= limit:
            return False
        STORE[bucket][key] = recent + [now]
        return True


# ============================================================================
# 2. DATABASE, ENCRYPTION AND ACCOUNTS
# ============================================================================
# Privacy design
# - Each user has a random data key. Their reports are encrypted with it (AES-256-GCM).
# - The data key is stored only in wrapped (encrypted) form: once with a key derived
# from the
# user's password, once with a key derived from their recovery code, and, while they're
# signed
# in, once with a key derived from their session token (which lives only in their
# browser's
#   address bar; the database holds just a hash of it).
# - So the database, and anyone who can read it (including the administrator), holds
# only
#   scrambled reports. Email addresses are never stored: only a one-way fingerprint.
# - Usage records hold the username, times and counts: never names, searches, answers or
# reports.
ADMIN_USERNAME = "katadmin"
USERNAME_RE = re.compile(r"^[a-z0-9_.-]{3,30}$")
MIN_PASSWORD = 10
CODE_MINUTES = 15
SESSION_DAYS = 7
MAX_CODES_PER_HOUR = 3
try:
    TZ = ZoneInfo(str(secret("TIMEZONE", "Australia/Melbourne")))
except Exception:
    TZ = ZoneInfo("Australia/Melbourne")

SCHEMA = [
    """CREATE TABLE IF NOT EXISTS idk_users (
        username TEXT PRIMARY KEY, pw_hash TEXT, kdf_salt TEXT, key_by_password TEXT,
        recovery_salt TEXT, key_by_recovery TEXT, email_fp TEXT, name_fp TEXT,
        name_lock_until DOUBLE PRECISION, created_at DOUBLE PRECISION,
        closed_at DOUBLE PRECISION, last_active DOUBLE PRECISION)""",
    """CREATE TABLE IF NOT EXISTS idk_sessions (
        token_hash TEXT PRIMARY KEY, username TEXT, key_by_token TEXT,
        started_at DOUBLE PRECISION, last_seen DOUBLE PRECISION,
        expires_at DOUBLE PRECISION, ended_at DOUBLE PRECISION)""",
    """CREATE TABLE IF NOT EXISTS idk_reports (
        id TEXT PRIMARY KEY, username TEXT, created_at DOUBLE PRECISION,
        title TEXT, summary_pdf TEXT, full_pdf TEXT)""",
    """CREATE TABLE IF NOT EXISTS idk_events (
        id TEXT PRIMARY KEY, username TEXT, kind TEXT, at DOUBLE PRECISION)""",
    """CREATE TABLE IF NOT EXISTS idk_sponsors (
        id TEXT PRIMARY KEY, name TEXT, headline TEXT, body TEXT, link TEXT, image TEXT,
        active INTEGER, impressions INTEGER, clicks INTEGER, created_at DOUBLE
        PRECISION)""",
]


def _database_url():
    try:
        return str(st.secrets["connections"]["idkat_db"]["url"])
    except Exception:
        return ""


@st.cache_resource
def _database():
    """The permanent database (e.g. Supabase). Without one, a local file is used for
    testing only:
    Streamlit Community Cloud deletes it whenever the app restarts."""
    url = _database_url()
    if url:
        engine = create_engine(url, pool_pre_ping=True, pool_size=3, max_overflow=2)
    else:
        engine = create_engine(
            "sqlite:///idkat_local.sqlite", connect_args={"check_same_thread": False}
        )
    with engine.begin() as conn:
        for statement in SCHEMA:
            conn.execute(sql_text(statement))
    return {"engine": engine, "local": not url}


DB = _database()


def db_run(sql, **params):
    with DB["engine"].begin() as conn:
        conn.execute(sql_text(sql), params)


def db_rows(sql, **params):
    with DB["engine"].begin() as conn:
        return [dict(r._mapping) for r in conn.execute(sql_text(sql), params)]


def db_one(sql, **params):
    rows = db_rows(sql, **params)
    return rows[0] if rows else None


def log_event(username, kind):
    db_run(
        "INSERT INTO idk_events (id, username, kind, at) VALUES (:id, :u, :k, :t)",
        id=uuid.uuid4().hex,
        u=username,
        k=kind,
        t=time.time(),
    )


# --- Encryption ---------------------------------------------------------------
def _b64e(data):
    return urlsafe_b64encode(data).decode()


def _b64d(value):
    return urlsafe_b64decode(str(value).encode())


def derive_key(secret_text, salt_hex):
    return hashlib.scrypt(
        str(secret_text).encode(),
        salt=bytes.fromhex(salt_hex),
        n=2**14,
        r=8,
        p=1,
        dklen=32,
    )


def seal(key, data):
    nonce = os.urandom(12)
    return _b64e(nonce + AESGCM(key).encrypt(nonce, data, None))


def unseal(key, sealed):
    raw = _b64d(sealed)
    return AESGCM(key).decrypt(raw[:12], raw[12:], None)


def token_key(token):
    return hashlib.sha256(b"idkat-session:" + str(token).encode()).digest()


def token_hash(token):
    return hashlib.sha256(str(token).encode()).hexdigest()


def new_recovery_code():
    return "-".join(pysecrets.token_hex(2).upper() for _ in range(5))


def clean_recovery(code):
    return re.sub(r"[^A-F0-9]", "", str(code or "").upper())


# --- Accounts -------------------------------------------------------------------
def get_user(username):
    return db_one("SELECT * FROM idk_users WHERE username = :u", u=username)


def email_in_use(email):
    return (
        db_one(
            "SELECT username FROM idk_users WHERE email_fp = :e AND closed_at IS NULL",
            e=fingerprint(email),
        )
        is not None
    )


def create_account(username, password, email):
    """Creates the account and returns (data key, recovery code). The recovery code is shown once."""
    data_key, recovery = os.urandom(32), new_recovery_code()
    kdf_salt, recovery_salt = pysecrets.token_hex(16), pysecrets.token_hex(16)
    now = time.time()
    db_run(
        """INSERT INTO idk_users (username, pw_hash, kdf_salt, key_by_password,
        recovery_salt,
              key_by_recovery, email_fp, created_at, last_active)
              VALUES (:u, :pw, :ks, :kp, :rs, :kr, :e, :t, :t)""",
        u=username,
        pw=bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode(),
        ks=kdf_salt,
        kp=seal(derive_key(password, kdf_salt), data_key),
        rs=recovery_salt,
        kr=seal(derive_key(clean_recovery(recovery), recovery_salt), data_key),
        e=fingerprint(email),
        t=now,
    )
    log_event(username, "account_created")
    return data_key, recovery


def check_password(password, hashed):
    if not hashed or len(str(password).encode()) > 72:
        return False
    try:
        return bcrypt.checkpw(str(password).encode(), str(hashed).encode())
    except ValueError:
        return False


def sign_in_user(username, password):
    """Returns the user's data key if the password is right, otherwise None."""
    user = get_user(username)
    if not user or user["closed_at"] or not check_password(password, user["pw_hash"]):
        return None
    try:
        return unseal(derive_key(password, user["kdf_salt"]), user["key_by_password"])
    except Exception:
        return None


def set_password(username, data_key, new_password):
    salt = pysecrets.token_hex(16)
    db_run(
        "UPDATE idk_users SET pw_hash = :pw, kdf_salt = :s, key_by_password = :k WHERE "
        "username = :u",
        pw=bcrypt.hashpw(new_password.encode(), bcrypt.gensalt()).decode(),
        s=salt,
        k=seal(derive_key(new_password, salt), data_key),
        u=username,
    )


def replace_recovery_code(username, data_key):
    recovery, salt = new_recovery_code(), pysecrets.token_hex(16)
    db_run(
        "UPDATE idk_users SET recovery_salt = :s, key_by_recovery = :k WHERE username "
        "= :u",
        s=salt,
        k=seal(derive_key(clean_recovery(recovery), salt), data_key),
        u=username,
    )
    return recovery


def reset_password(username, new_password, recovery=""):
    """With the recovery code, saved reports are kept. Without it, they can't be
    decrypted, so they're
    deleted and a fresh key is made. Returns (kept_reports, new recovery code or None).
    """
    user = get_user(username)
    if recovery:
        try:
            data_key = unseal(
                derive_key(clean_recovery(recovery), user["recovery_salt"]),
                user["key_by_recovery"],
            )
        except Exception:
            return None, None
        set_password(username, data_key, new_password)
        log_event(username, "password_reset")
        return True, None
    data_key = os.urandom(32)
    db_run("DELETE FROM idk_reports WHERE username = :u", u=username)
    set_password(username, data_key, new_password)
    code = replace_recovery_code(username, data_key)
    log_event(username, "password_reset_reports_deleted")
    return False, code


def close_account(username):
    """Deletes reports, credentials and keys. Keeps only the username, dates and usage counts."""
    db_run("DELETE FROM idk_reports WHERE username = :u", u=username)
    db_run(
        """UPDATE idk_users SET pw_hash = NULL, kdf_salt = NULL, key_by_password = NULL,
              recovery_salt = NULL, key_by_recovery = NULL, closed_at = :t WHERE
              username = :u""",
        t=time.time(),
        u=username,
    )
    db_run(
        "UPDATE idk_sessions SET key_by_token = NULL, ended_at = :t WHERE username = "
        ":u AND ended_at IS NULL",
        t=time.time(),
        u=username,
    )
    log_event(username, "account_closed")


def name_lock(username):
    user = get_user(username)
    if user and user["name_fp"] and (user["name_lock_until"] or 0) > time.time():
        return user["name_fp"]
    return None


def set_name_lock(username, name):
    db_run(
        "UPDATE idk_users SET name_fp = :n, name_lock_until = :t WHERE username = :u",
        n=fingerprint(name),
        t=time.time() + NAME_LOCK_DAYS * 86400,
        u=username,
    )


# --- Sessions -------------------------------------------------------------------
def start_session(username, data_key=None):
    token = pysecrets.token_urlsafe(32)
    now = time.time()
    db_run(
        """INSERT INTO idk_sessions (token_hash, username, key_by_token, started_at,
        last_seen, expires_at)
              VALUES (:h, :u, :k, :t, :t, :e)""",
        h=token_hash(token),
        u=username,
        k=seal(token_key(token), data_key) if data_key else None,
        t=now,
        e=now + SESSION_DAYS * 86400,
    )
    db_run(
        "UPDATE idk_users SET last_active = :t WHERE username = :u", t=now, u=username
    )
    st.query_params["s"] = token
    st.session_state.user = username
    st.session_state.data_key = data_key
    return token


def restore_session(token):
    row = db_one(
        "SELECT * FROM idk_sessions WHERE token_hash = :h", h=token_hash(token)
    )
    if not row or row["ended_at"] or row["expires_at"] < time.time():
        return False
    if row["username"] != ADMIN_USERNAME:
        user = get_user(row["username"])
        if not user or user["closed_at"] or not row["key_by_token"]:
            return False
        try:
            st.session_state.data_key = unseal(token_key(token), row["key_by_token"])
        except Exception:
            return False
    st.session_state.user = row["username"]
    return True


def touch_session():
    """Records activity at most once a minute: used for session length and last-active dates."""
    token, now = st.query_params.get("s"), time.time()
    if token and now - st.session_state.get("_touched", 0) > 60:
        st.session_state["_touched"] = now
        db_run(
            "UPDATE idk_sessions SET last_seen = :t WHERE token_hash = :h",
            t=now,
            h=token_hash(token),
        )
        if st.session_state.get("user") != ADMIN_USERNAME:
            db_run(
                "UPDATE idk_users SET last_active = :t WHERE username = :u",
                t=now,
                u=st.session_state.user,
            )


def end_session():
    token = st.query_params.get("s")
    if token:
        db_run(
            "UPDATE idk_sessions SET key_by_token = NULL, ended_at = :t WHERE "
            "token_hash = :h",
            t=time.time(),
            h=token_hash(token),
        )
    for key in list(st.session_state.keys()):
        del st.session_state[key]
    st.query_params.clear()


# --- Reports library ------------------------------------------------------------
def save_report(username, data_key, title, summary, full):
    db_run(
        """INSERT INTO idk_reports (id, username, created_at, title, summary_pdf,
        full_pdf)
              VALUES (:id, :u, :t, :ti, :s, :f)""",
        id=uuid.uuid4().hex,
        u=username,
        t=time.time(),
        ti=seal(data_key, title.encode()),
        s=seal(data_key, summary),
        f=seal(data_key, full),
    )
    log_event(username, "report_saved")


def list_reports(username, data_key):
    reports = []
    for row in db_rows(
        "SELECT id, created_at, title FROM idk_reports WHERE username = :u ORDER BY "
        "created_at DESC",
        u=username,
    ):
        try:
            title = unseal(data_key, row["title"]).decode()
        except Exception:
            title = "Report (can't be opened)"
        reports.append(
            {"id": row["id"], "created_at": row["created_at"], "title": title}
        )
    return reports


def open_report(username, data_key, report_id, which):
    row = db_one(
        f"SELECT {which} FROM idk_reports WHERE id = :id AND username = :u",
        id=report_id,
        u=username,
    )
    return unseal(data_key, row[which]) if row else b""


def delete_report(username, report_id):
    db_run(
        "DELETE FROM idk_reports WHERE id = :id AND username = :u",
        id=report_id,
        u=username,
    )
    log_event(username, "report_deleted")


def local_time(ts, fmt="%d %b %Y %H:%M"):
    return datetime.datetime.fromtimestamp(ts, TZ).strftime(fmt) if ts else ""


# --- Sponsors (privacy-friendly advertising) ------------------------------------
def active_sponsors():
    return db_rows("SELECT * FROM idk_sponsors WHERE active = 1 ORDER BY created_at")


def sponsor_count(sponsor_id, column):
    db_run(
        f"UPDATE idk_sponsors SET {column} = {column} + 1 WHERE id = :id", id=sponsor_id
    )


def render_sponsor():
    """One clearly labelled sponsored card. No third-party scripts, cookies or remote
    images:
    sponsors only receive visitors who choose to click through, and nothing about them.
    """
    sponsors = active_sponsors()
    if not sponsors:
        return
    pick_index = st.session_state.setdefault("sponsor_pick", pysecrets.randbelow(10**6))
    sponsor = sponsors[pick_index % len(sponsors)]
    seen = st.session_state.setdefault("sponsors_seen", set())
    if sponsor["id"] not in seen:
        seen.add(sponsor["id"])
        sponsor_count(sponsor["id"], "impressions")
    image = ""
    if sponsor.get("image") and ";" in sponsor["image"]:
        mime, data = sponsor["image"].split(";", 1)
        image = (
            f"<img src='data:{mime};base64,{data}' style='max-width:100%;"
            "margin:6px 0;border-radius:2px;'>"
        )
    st.markdown(
        "<div style='background:#1A1814;border:1px solid #2C2822;padding:12px 14px;"
        "border-radius:2px;'>"
        "<div style='font-size:0.65rem;letter-spacing:0.2em;color:#C6BCA9;"
        "text-transform:uppercase;'>Sponsored</div>"
        f"{image}<div style='color:#F2EDE3;font-weight:600;'>"
        f"{html.escape(sponsor['headline'] or sponsor['name'])}</div>"
        "<div style='color:#C6BCA9;font-size:0.85rem;'>"
        f"{html.escape(sponsor['body'] or '')}</div></div>",
        unsafe_allow_html=True,
    )
    clicked = st.session_state.setdefault("sponsors_clicked", set())
    if sponsor["id"] in clicked:
        st.link_button(f"Open {sponsor['name']} ↗", sponsor["link"], width="stretch")
    elif st.button("Learn more", key=f"sponsor_{sponsor['id']}", width="stretch"):
        clicked.add(sponsor["id"])
        sponsor_count(sponsor["id"], "clicks")
        st.rerun()
    st.caption("IDkat never shares anything about you with sponsors.")


# --- Email (verification codes and optional report copies) -----------------------
def smtp_ready():
    return all(secret(k) for k in ("SMTP_HOST", "SMTP_USER", "SMTP_PASSWORD"))


def send_email(to, subject, body, attachments=()):
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = str(secret("SMTP_FROM", secret("SMTP_USER")))
    msg["To"] = to
    msg.set_content(body)
    for name, data in attachments:
        msg.add_attachment(data, maintype="application", subtype="pdf", filename=name)
    host, port = str(secret("SMTP_HOST")), int(secret("SMTP_PORT", 587))
    context = ssl.create_default_context()
    if port == 465:
        server = smtplib.SMTP_SSL(host, port, context=context, timeout=30)
    else:
        server = smtplib.SMTP(host, port, timeout=30)
        server.starttls(context=context)
    with server:
        server.login(str(secret("SMTP_USER")), str(secret("SMTP_PASSWORD")))
        server.send_message(msg)


def send_code(email, purpose):
    """Emails a 6-digit code. Only a hash of the code is kept, in this browser session."""
    code = f"{pysecrets.randbelow(10**6):06d}"
    st.session_state[f"code_{purpose}"] = {
        "hash": hashlib.sha256(code.encode()).hexdigest(),
        "until": time.time() + CODE_MINUTES * 60,
        "tries": 0,
    }
    send_email(
        email,
        f"Your IDkat code: {code}",
        f"Your IDkat verification code is {code}. It expires in {CODE_MINUTES} "
        "minutes.\n\n"
        "If you didn't ask for this, you can ignore this email.\n",
    )


def check_code(purpose, code):
    pending = st.session_state.get(f"code_{purpose}")
    if not pending or pending["until"] < time.time() or pending["tries"] >= 5:
        return False
    pending["tries"] += 1
    return hmac.compare_digest(
        pending["hash"], hashlib.sha256(str(code).strip().encode()).hexdigest()
    )


CONSENT_TEXT = (
    "By creating an account, you confirm that:\n"
    "- you'll use IDkat to check information about yourself only, not anyone else;\n"
    "- your name, any other names and your city (if you give them) are used to search "
    "the public web, "
    "processed by Google's Gemini AI service. Your email address and occupation are "
    "only used in a search "
    "if you choose that. The details you give to confirm which pages are yours never "
    "leave IDkat;\n"
    "- your reports are saved in your library in encrypted form. Only you can open "
    "them, with your password "
    "or your recovery code. If you lose both, they can't be recovered by anyone;\n"
    "- IDkat keeps your username and simple usage records (when your account was "
    "created, when you use it, "
    "and how many searches and reports you make). These are used to run IDkat and to "
    "give sponsors "
    "combined statistics that never identify you. Your email address is never stored, "
    "only a scrambled "
    "fingerprint of it;\n"
    "- IDkat is free because of clearly labelled sponsored messages. Sponsors never "
    "receive anything about you."
)


# ============================================================================
# 3. SEARCH ENGINE (runs in the background; no Streamlit calls inside)
# ============================================================================
class Detail(BaseModel):
    kind: str = Field(
        description="One of: Place, Workplace, Education, Occupation, Username, "
        "Interest, Public profile."
    )
    value: str = Field(
        description="The detail as shown on the page, e.g. 'Geelong', 'Acme Pty Ltd', "
        "'@jsmith'."
    )


class Exposure(BaseModel):
    site: str = Field(description="The website's name.")
    page_type: str = Field(
        default="Other", description="One of: " + ", ".join(PAGE_TYPES) + "."
    )
    exposed: list[str] = Field(
        default=[],
        description="Types of personal information the page exposes, from: "
        + ", ".join(EXPOSED_TYPES)
        + ". Types only, never the values.",
    )
    details: list[Detail] = Field(
        default=[],
        description="Identifying details shown on the page that help tell "
        "people with the same name apart: place, workplace, education, occupation, "
        "username, "
        "hobbies or sports (Interest), and whether the person is a public figure such "
        "as an "
        "athlete, politician or entertainer (Public profile).",
    )
    removal: str = Field(
        description="How the person can remove or hide it, in one or two practical "
        "sentences."
    )
    removal_link: str = Field(
        default="None",
        description="An opt-out or settings page, copied exactly from the verified "
        "list, else 'None'.",
    )
    effort: str = Field(default="Moderate", description="Quick, Moderate or Hard.")
    source_url: str = Field(
        default="None",
        description="The page, copied exactly from the verified list, else 'None'.",
    )


class ExposureExtraction(BaseModel):
    exposures: list[Exposure] = []


EMAIL_RE = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+")
PHONE_RE = re.compile(r"(?:\+?\d[\d\s().-]{7,}\d)")
STREET_RE = re.compile(
    r"\b\d{1,5}\s+[A-Z][a-z]+(?:\s+[A-Z][a-z]+)*\s+(?:St|Street|Rd|Road|Ave|Avenue|Dr|"
    r"Drive|"
    r"Ct|Court|Pl|Place|Cres|Crescent|Pde|Parade|Hwy|Highway|Lane|Ln|Tce|Terrace|Way|"
    r"Blvd)\b"
)


def scrub(text):
    """Removes any contact details that slip into the text: reports describe types of information only."""
    text = EMAIL_RE.sub("[email hidden]", str(text or ""))
    text = STREET_RE.sub("[address hidden]", text)

    def hide(match):
        value = match.group()
        if re.fullmatch(r"\s*(19|20)\d{2}\s*[-–]\s*(19|20)\d{2}\s*", value):
            return value  # a year range, not a phone number
        return "[number hidden]" if len(re.sub(r"\D", "", value)) >= 8 else value

    return PHONE_RE.sub(hide, text)


def is_url(value):
    v = str(value or "").strip()
    return v.startswith("http") and v.lower() not in ("none", "null")


def norm_url(url):
    if not is_url(url):
        return ""
    p = urlparse(url.strip())
    return f"{p.netloc.lower().removeprefix('www.')}{p.path.rstrip('/')}"


def resolve_redirect(uri):
    headers = {"User-Agent": "Mozilla/5.0 (IDkat link check)"}
    status, final = None, ""
    try:
        r = requests.head(uri, allow_redirects=True, timeout=6, headers=headers)
        status, final = r.status_code, r.url
        if status in (403, 405) or status >= 500:
            r = requests.get(
                uri, allow_redirects=True, timeout=8, headers=headers, stream=True
            )
            r.close()
            status, final = r.status_code, r.url
    except requests.RequestException as exc:
        resp = getattr(exc, "response", None)
        if resp is not None:
            status, final = resp.status_code, resp.url
    if status is not None and status < 400:
        return final
    blocked = status in (401, 403, 429, 999)
    dom = urlparse(final).netloc.lower() if final else ""
    if (
        blocked
        and dom
        and dom != urlparse(uri).netloc.lower()
        and not dom.endswith("google.com")
    ):
        return final
    return ""


def pick(value, options, default):
    text = str(value or "").strip().lower()
    return next(
        (
            o
            for o in options
            if o.lower() == text or o.lower().split(" ")[0] == text.split(" ")[0]
        ),
        default,
    )


def model_client(api_key):
    key = re.sub(r"[^\w.\-]", "", str(api_key or "").strip())
    return genai.Client(api_key=key, vertexai=False, enterprise=False)


def generate(client, model, prompt, schema=None, search=False):
    config = types.GenerateContentConfig(temperature=0.2)
    if search:
        config = types.GenerateContentConfig(
            tools=[types.Tool(google_search=types.GoogleSearch())], temperature=0.2
        )
    if schema is not None:
        config = types.GenerateContentConfig(
            response_mime_type="application/json", response_schema=schema, temperature=0
        )
    try:
        return client.models.generate_content(
            model=model, contents=prompt, config=config
        )
    except Exception as exc:
        if "not found" in str(exc).lower() and model != FALLBACK_MODEL:
            return client.models.generate_content(
                model=FALLBACK_MODEL, contents=prompt, config=config
            )
        raise


def search_prompt(profile, focus):
    aka = f" They may also appear as: {profile['aka']}." if profile["aka"] else ""
    where = (
        f" They are based in or connected to {profile['location']}."
        if profile["location"]
        else ""
    )
    email = (
        f" Also look for pages where their email address {profile['email']} appears."
        if profile["include_email"]
        else ""
    )
    work = (
        f" They work as: {profile['occupation']}." if profile.get("occupation") else ""
    )
    extra = f" Also search for: {profile['extra']}." if profile.get("extra") else ""
    return f"""Today is {datetime.date.today():%d %B %Y}.
You are helping a person find where their OWN personal information appears on the public
web, so they can
remove it. They have signed in with a verified email and confirmed they are searching
for themselves.
Person: "{profile['name']}".{aka}{where}{work}{email}{extra}
Focus this search on: {focus}.
For each page found, report: the site, the page URL, what KINDS of personal information
it exposes (for
example home address, phone number, email, date of birth or age, photos, workplace,
relatives, usernames),
how the person could get it removed or hidden (including any opt-out or privacy-settings
page), and any
general identifying details that help tell people with the same name apart: the city or
region, workplace,
school or university, occupation, username, hobbies or sports, and whether the person is
a public figure (for
example a professional athlete, politician or entertainer).
Never repeat home addresses, phone numbers, email addresses, dates of birth or ID
numbers. Report only what
the search results show."""


def extraction_prompt(profile, notes, sources):
    listing = "\n".join(f"- {url}  ({title})" for title, url in sources) or "(none)"
    return f"""Convert the notes below into JSON matching the schema, for a person
    checking their own online
exposure ("{profile['name']}").

RULES
1. One entry per page. source_url and removal_link must be copied EXACTLY from the
VERIFIED SOURCES list,
otherwise 'None'.
2. exposed: types only, from the allowed list. Never include the actual values.
3. details: only general identifying details shown on the page, with kind Place (city,
suburb or region
only), Workplace, Education, Occupation, Username, Interest (hobbies, sports, clubs) or
Public profile (only
if the person is a public figure: e.g. 'professional footballer', 'politician',
'actor'). Never street
addresses, phone numbers, email addresses, dates of birth or ID numbers.
4. removal: practical steps in one or two sentences. effort: Quick, Moderate or Hard.

VERIFIED SOURCES
{listing}

NOTES
{notes[:25000]}"""


def hibp_breaches(email):
    """Optional: data breaches involving the email, via Have I Been Pwned (needs HIBP_API_KEY)."""
    key = secret("HIBP_API_KEY")
    if not key:
        return None
    try:
        r = requests.get(
            "https://haveibeenpwned.com/api/v3/breachedaccount/"
            f"{requests.utils.quote(email)}",
            params={"truncateResponse": "false"},
            timeout=10,
            headers={"hibp-api-key": str(key), "user-agent": "IDkat"},
        )
        if r.status_code == 404:
            return []
        if r.status_code != 200:
            return None
        return [
            {
                "name": b.get("Title") or b.get("Name"),
                "date": b.get("BreachDate", ""),
                "data": ", ".join((b.get("DataClasses") or [])[:6]),
            }
            for b in r.json()
        ]
    except (requests.RequestException, ValueError):
        return None


# Questions ask about YOU, never about a page, so answering reveals nothing about anyone
# else.
QUESTIONS = {
    "Place": "Where have you lived in the last 10 years? Include suburbs and cities.",
    "Workplace": "Where have you worked? Include past employers.",
    "Education": "Where have you studied? Schools, TAFEs or universities.",
    "Occupation": "What work do you do, or have you done? (e.g. teacher, engineer)",
    "Username": "Usernames or handles you use (e.g. @willw, willwright88)",
    "Interest": "Hobbies, sports or clubs you're known for (e.g. running, Collingwood "
    "FC, choir)",
}
PUBLIC_OPTIONS = [
    "No",
    "Yes, through my work (e.g. spokesperson, academic, business leader)",
    "Yes, widely known (e.g. sport, entertainment, politics)",
]
NO_CONFLICT_KINDS = {
    "Username",
    "Interest",
}  # people have many handles and hobbies; a different one isn't a conflict
DETAIL_KINDS = list(QUESTIONS)


def split_answers(text):
    return [p.strip() for p in re.split(r"[,;\n]+", str(text or "")) if p.strip()]


def simplify(value):
    return re.sub(r"[^a-z0-9 ]", " ", str(value or "").lower()).split()


def same_thing(a, b):
    """True if two short answers refer to the same thing, e.g. 'RMIT' and 'RMIT University'."""
    ta, tb = simplify(a), simplify(b)
    if not ta or not tb:
        return False
    ja, jb = "".join(ta), "".join(tb)
    if ja in jb or jb in ja:
        return True
    shorter = min(len(set(ta)), len(set(tb)))
    return shorter > 0 and len(set(ta) & set(tb)) / shorter >= 0.6


def own_link(item, clues):
    url = norm_url(item.get("url"))
    return bool(url) and any(
        norm_url(link) and (url == norm_url(link) or url.startswith(norm_url(link)))
        for link in clues.get("Links", [])
    )


def assess(item, clues):
    """Decides privately, in code, whether a page is yours. Nothing here leaves IDkat.
    Returns ('verified' | 'someone else' | 'unverified', kinds still unanswered)."""
    if own_link(item, clues):
        return "verified", []
    handles = [h.lstrip("@").lower() for h in clues.get("Username", [])]
    url = str(item.get("url") or "").lower()
    if handles and any(h and len(h) >= 4 and h in url for h in handles):
        return "verified", []
    matched, conflicts, unanswered = set(), set(), set()
    public = clues.get("Public", "")
    for detail in item.get("details", []):
        kind = detail.get("kind")
        if kind == "Public profile":
            if public.startswith("No"):
                conflicts.add(
                    kind
                )  # a public figure's page, but you're not a public figure
            elif public.startswith("Yes"):
                described = clues.get("Public description", [])
                if described and any(
                    same_thing(detail.get("value"), d) for d in described
                ):
                    matched.add(kind)
                elif described:
                    conflicts.add(kind)
            else:
                unanswered.add("Public")
            continue
        if kind not in DETAIL_KINDS:
            continue
        answers = clues.get(kind)
        if not answers:
            unanswered.add(kind)
        elif any(same_thing(detail.get("value"), a) for a in answers):
            matched.add(kind)
        elif kind not in NO_CONFLICT_KINDS:
            conflicts.add(kind)
    if "Username" in matched:
        return "verified", []
    if conflicts and not matched:
        return "someone else", []
    if len(matched) >= 2 and not conflicts:
        return "verified", []
    if conflicts:
        return "unverified", []
    return "unverified", sorted(unanswered)


def sort_out(items, clues):
    """Splits results into verified pages, pages about other people, and pages that can't be verified yet."""
    verified, others, unverified, questions = [], 0, 0, set()
    for item in items:
        outcome, missing = assess(item, clues)
        if outcome == "verified":
            verified.append(item)
        elif outcome == "someone else":
            others += 1
        else:
            unverified += 1
            questions.update(missing)
    verified.sort(
        key=lambda i: (not (HIGH_TYPES & set(i["exposed"])), EFFORTS.index(i["effort"]))
    )
    return (
        verified,
        others,
        unverified,
        [k for k in DETAIL_KINDS + ["Public"] if k in questions],
    )


def exposure_level(verified):
    high = [i for i in verified if HIGH_TYPES & set(i["exposed"])]
    if len(high) >= 2:
        return "High"
    if high or len(verified) >= 3:
        return "Moderate"
    return "Low" if verified else "Minimal"


def left_out_text(others, unverified):
    parts = []
    if others:
        parts.append(
            f"{others} page{'s' if others != 1 else ''} about other people with your "
            "name"
        )
    if unverified:
        parts.append(
            f"{unverified} page{'s' if unverified != 1 else ''} that couldn't be "
            "confirmed as yours"
        )
    return (
        ("Left out: " + " and ".join(parts) + ". Nothing about them is shown or kept.")
        if parts
        else ""
    )


def search_pass(client, model, job, profile, group, label):
    job["progress"] = label
    resp = generate(
        client,
        model,
        search_prompt(profile, "; ".join(CHANNELS[c] for c in group)),
        search=True,
    )
    sources = []
    for cand in getattr(resp, "candidates", None) or []:
        meta = getattr(cand, "grounding_metadata", None)
        for chunk in (getattr(meta, "grounding_chunks", None) or []) if meta else []:
            web = getattr(chunk, "web", None)
            if web and getattr(web, "uri", None):
                final = resolve_redirect(
                    web.uri
                )  # real addresses, so duplicates can be recognised
                if final:
                    sources.append((getattr(web, "title", "") or "", final))
    allowed = {norm_url(u) for _, u in sources}
    notes = resp.text or ""
    if not notes.strip():
        return 0
    job["progress"] = label.replace("Search", "Reading results from search", 1)
    data = generate(
        client,
        model,
        extraction_prompt(profile, notes, sources),
        schema=ExposureExtraction,
    )
    parsed = getattr(data, "parsed", None)
    raw = (
        parsed.model_dump()
        if isinstance(parsed, BaseModel)
        else json.loads(
            re.sub(r"^```(?:json)?\s*|\s*```$", "", (data.text or "").strip()) or "{}"
        )
    )
    added = 0
    for e in raw.get("exposures", []):
        item = {
            "site": scrub(e.get("site"))[:80] or "Unknown site",
            "page_type": pick(e.get("page_type"), PAGE_TYPES, "Other"),
            "exposed": list(
                dict.fromkeys(
                    pick(x, EXPOSED_TYPES, "Other") for x in e.get("exposed", [])
                )
            )[:8]
            or ["Other"],
            "details": [
                {
                    "kind": pick(d.get("kind"), DETAIL_KINDS + ["Public profile"], ""),
                    "value": scrub(d.get("value"))[:80],
                }
                for d in e.get("details", [])
                if d.get("value")
            ],
            "removal": scrub(e.get("removal"))[:400],
            "effort": pick(e.get("effort"), EFFORTS, "Moderate"),
            "url": (
                e.get("source_url") if norm_url(e.get("source_url")) in allowed else ""
            ),
            "removal_link": (
                e.get("removal_link")
                if norm_url(e.get("removal_link")) in allowed
                else ""
            ),
        }
        key = (
            norm_url(item["url"])
            or f"{normalize_site(item['site'])}|{item['page_type']}"
        )
        if key not in job["seen"]:
            job["seen"].add(key)
            item["key"] = key
            job["items"].append(item)
            added += 1
    return added


def normalize_site(site):
    return re.sub(r"[^a-z0-9]", "", str(site).lower())


def finish_job(job, profile, notify):
    job["finished"] = datetime.datetime.now().strftime("%d %b %Y %H:%M")
    job["status"] = "done"


def run_scan(job, profile, channels, api_key, model):
    """The background search. Results are held in memory only, and each pass is added as
    it
    finishes so you can start checking results straight away."""
    try:
        client = model_client(api_key)
        groups = [
            g
            for g in (
                channels[: (len(channels) + 1) // 2],
                channels[(len(channels) + 1) // 2 :],
            )
            if g
        ]
        for n, group in enumerate(groups, 1):
            search_pass(
                client,
                model,
                job,
                profile,
                group,
                f"Search {n} of {len(groups)}: {', '.join(group).lower()}",
            )
        if profile["include_email"]:
            job["progress"] = "Checking data breaches"
            job["breaches"] = hibp_breaches(profile["email"])
        finish_job(job, profile, notify=True)
    except Exception as exc:
        job["status"], job["error"] = (
            "failed",
            f"The search couldn't be completed: {str(exc)[:300]}",
        )


def run_refine(job, profile, channels, api_key, model):
    """One more search with extra details, added to the same results without duplicates."""
    try:
        before = len(job["items"])
        search_pass(
            model_client(api_key),
            model,
            job,
            profile,
            channels,
            "Search again with your extra details",
        )
        job["last_added"] = len(job["items"]) - before
        finish_job(job, profile, notify=False)
    except Exception as exc:
        job["status"], job["last_added"] = "done", 0
        job["refine_error"] = (
            f"The extra search couldn't be completed: {str(exc)[:200]}"
        )


MAX_REFINES = 2


def start_refine(job, extra):
    profile = dict(job["profile"], extra=extra)
    job.update(
        status="running",
        progress="Starting",
        refines=job.get("refines", 0) + 1,
        refine_error="",
    )
    api_key = str(secret("GEMINI_API_KEY", "") or "")
    model = str(secret("GEMINI_MODEL", DEFAULT_MODEL))
    threading.Thread(
        target=run_refine,
        args=(job, profile, job["channels"], api_key, model),
        daemon=True,
    ).start()


def start_scan(email, profile, channels):
    job = {
        "id": uuid.uuid4().hex[:12],
        "owner": fingerprint(email),
        "status": "running",
        "progress": "Starting",
        "started": time.time(),
        "items": [],
        "seen": set(),
        "breaches": None,
        "name": profile["name"],
        "finished": "",
        "error": "",
        "profile": profile,
        "channels": channels,
        "refines": 0,
    }
    with STORE["lock"]:
        STORE["jobs"][job["id"]] = job
    api_key = str(secret("GEMINI_API_KEY", "") or "")
    model = str(secret("GEMINI_MODEL", DEFAULT_MODEL))
    threading.Thread(
        target=run_scan, args=(job, profile, channels, api_key, model), daemon=True
    ).start()


def my_job(email):
    owner = fingerprint(email)
    jobs = [j for j in list(STORE["jobs"].values()) if j["owner"] == owner]
    return max(jobs, key=lambda j: j["started"]) if jobs else None


def delete_my_results(email):
    owner = fingerprint(email)
    with STORE["lock"]:
        for job_id in [j for j, job in STORE["jobs"].items() if job["owner"] == owner]:
            del STORE["jobs"][job_id]


# ============================================================================
# 4. REPORTS
# ============================================================================
def _pdf_fonts():
    base = Path(matplotlib.get_data_path()) / "fonts" / "ttf"
    files = {
        "": "DejaVuSans.ttf",
        "B": "DejaVuSans-Bold.ttf",
        "I": "DejaVuSans-Oblique.ttf",
    }
    found = {k: base / v for k, v in files.items()}
    return found if all(p.exists() for p in found.values()) else None


PDF_FONTS = _pdf_fonts()
FONT = "IDkatSans" if PDF_FONTS else "Helvetica"


def pdf_text(text):
    text = re.sub("[\U0001f000-\U0001faff\u2600-\u27bf\ufe0f]", "", str(text or ""))
    return text if PDF_FONTS else text.encode("latin-1", "replace").decode("latin-1")


def hex_rgb(value):
    value = value.lstrip("#")
    return tuple(int(value[i : i + 2], 16) for i in (0, 2, 4))


class Report(FPDF):
    def __init__(self):
        super().__init__()
        if PDF_FONTS:
            for style, path in PDF_FONTS.items():
                self.add_font(FONT, style, str(path))
        self.set_margins(16, 18, 16)
        self.set_auto_page_break(auto=True, margin=16)

    def footer(self):
        self.set_y(-12)
        self.set_font(FONT, "", 8)
        self.set_text_color(*hex_rgb(MUTED))
        self.cell(
            0,
            5,
            pdf_text(f"IDkat · confidential to you · page {self.page_no()}"),
            align="C",
        )

    def multi_cell(self, *args, **kwargs):
        kwargs.setdefault("new_x", "LMARGIN")
        kwargs.setdefault("new_y", "NEXT")
        return super().multi_cell(*args, **kwargs)

    def band(self, title, subtitle):
        self.add_page()
        self.set_fill_color(*hex_rgb(INK))
        self.rect(0, 0, self.w, 36, "F")
        self.set_xy(16, 8)
        self.set_font(FONT, "B", 9)
        self.set_text_color(*hex_rgb(SAND))
        self.cell(0, 4, "IDKAT · YOUR ONLINE FOOTPRINT", new_x="LMARGIN", new_y="NEXT")
        self.set_font(FONT, "B", 18)
        self.set_text_color(*hex_rgb(BONE))
        self.cell(0, 9, pdf_text(title), new_x="LMARGIN", new_y="NEXT")
        self.set_font(FONT, "I", 10)
        self.set_text_color(*hex_rgb(SAND))
        self.cell(0, 6, pdf_text(subtitle), new_x="LMARGIN", new_y="NEXT")
        self.set_y(42)

    def cards(self, cards):
        gap, height = 3, 21
        width = (self.epw - gap * (len(cards) - 1)) / len(cards)
        top = self.get_y()
        for i, (label, value) in enumerate(cards):
            x = self.l_margin + i * (width + gap)
            self.set_fill_color(*hex_rgb(BONE))
            self.set_draw_color(*hex_rgb(SAND))
            self.rect(x, top, width, height, "DF")
            self.set_xy(x, top + 3)
            size = 7.5
            self.set_font(FONT, "B", size)
            while (
                self.get_string_width(pdf_text(label.upper())) > width - 3
                and size > 5.5
            ):
                size -= 0.25
                self.set_font(FONT, "B", size)
            self.set_text_color(*hex_rgb(MUTED))
            self.cell(width, 5, pdf_text(label.upper()), align="C")
            self.set_xy(x, top + 10)
            self.set_font(FONT, "B", 14)
            self.set_text_color(*hex_rgb(INK))
            self.cell(width, 6, pdf_text(value), align="C")
        self.set_xy(self.l_margin, top + height + 5)

    def section(self, title, body=""):
        if self.get_y() > self.page_break_trigger - 18:
            self.add_page()
        self.set_font(FONT, "B", 12.5)
        self.set_text_color(*hex_rgb(INK))
        self.cell(self.epw, 7, pdf_text(title), new_x="LMARGIN", new_y="NEXT")
        if body:
            self.set_font(FONT, "", 10)
            self.set_text_color(25, 25, 25)
            self.multi_cell(self.epw, 5, pdf_text(body))
        self.ln(2)

    def item(self, colour, heading, lines):
        if self.get_y() > self.page_break_trigger - 14:
            self.add_page()
        y = self.get_y()
        self.set_fill_color(*hex_rgb(colour))
        self.rect(self.l_margin, y + 1.2, 2.8, 2.8, "F")
        self.set_x(self.l_margin + 5)
        self.set_font(FONT, "B", 10)
        self.set_text_color(*hex_rgb(INK))
        self.multi_cell(self.epw - 5, 4.8, pdf_text(heading))
        for style, text in lines:
            self.set_x(self.l_margin + 5)
            self.set_font(FONT, style, 9)
            self.set_text_color(35, 35, 35)
            self.multi_cell(self.epw - 5, 4.4, pdf_text(text))
        self.ln(1.5)


def item_colour(item):
    return "#B5654F" if HIGH_TYPES & set(item["exposed"]) else "#C6A15B"


def top_actions(verified, n=5):
    return verified[:n]


def summary_pdf(report):
    verified = report["verified"]
    pdf = Report()
    pdf.band(f"Summary for {report['name']}", f"Generated {report['finished']}")
    pdf.cards(
        [
            ("Exposure level", exposure_level(verified)),
            ("Pages confirmed as yours", str(len(verified))),
            (
                "Sensitive details",
                str(sum(1 for i in verified if HIGH_TYPES & set(i["exposed"]))),
            ),
            ("Quick fixes", str(sum(1 for i in verified if i["effort"] == "Quick"))),
        ]
    )
    kinds = sorted({t for i in verified for t in i["exposed"]})
    pdf.section(
        "What's out there",
        (
            ("Pages confirmed as yours expose: " + ", ".join(kinds).lower() + ".")
            if kinds
            else "We didn't find pages we could confirm as yours."
        ),
    )
    actions = top_actions(verified)
    if actions:
        pdf.section("Your top actions")
        for a in actions:
            pdf.item(
                item_colour(a),
                f"{a['site']} ({a['page_type'].lower()}): "
                f"{', '.join(a['exposed']).lower()}",
                [("", a["removal"])],
            )
    if report.get("breaches"):
        pdf.section(
            "Data breaches",
            f"Your email appears in {len(report['breaches'])} known data breach(es). "
            "Change those passwords and turn on multi-factor authentication.",
        )
    left_out = left_out_text(report["others"], report["unverified"])
    pdf.section(
        "Next",
        "Your full report has step-by-step removal guidance for every page confirmed "
        "as yours. "
        + (left_out + " " if left_out else "")
        + "IDkat has now deleted your results.",
    )
    return bytes(pdf.output())


def full_pdf(report):
    verified = report["verified"]
    pdf = Report()
    pdf.band(
        f"Full report and action plan: {report['name']}",
        f"Generated {report['finished']}",
    )
    pdf.section(
        "How to read this report",
        "Each entry is a page confirmed as yours: where your information "
        "appears, what kind of information it is, and how to remove or hide it. IDkat "
        "never repeats the "
        "details themselves. Red markers show sensitive details (such as your address, "
        "phone number or "
        "date of birth); amber markers show other details. Start with red, quick fixes.",
    )
    pdf.section(f"Pages confirmed as yours ({len(verified)})")
    for i in verified:
        link = f" Opt-out or settings: {i['removal_link']}" if i["removal_link"] else ""
        pdf.item(
            item_colour(i),
            f"{i['site']} · {i['page_type']}",
            [
                ("", "Exposes: " + ", ".join(i["exposed"]).lower()),
                ("", f"What to do ({i['effort'].lower()}): {i['removal']}{link}"),
                ("I", f"Page: {i['url'] or 'no verified link'}"),
            ],
        )
    left_out = left_out_text(report["others"], report["unverified"])
    if left_out:
        pdf.section(
            "Pages left out",
            left_out
            + " IDkat only includes pages it could confirm as yours, using the "
            "details you gave. Those details never left IDkat and have now been "
            "deleted.",
        )
    if report.get("breaches"):
        pdf.section("Data breaches involving your email")
        for b in report["breaches"]:
            pdf.item(
                "#B5654F", f"{b['name']} ({b['date']})", [("", f"Exposed: {b['data']}")]
            )
    elif report.get("breaches") == []:
        pdf.section("Data breaches", "Your email wasn't found in known data breaches.")
    pdf.section("General recommendations")
    for title, text in GENERAL_ADVICE:
        pdf.item(SAND, title, [("", text)])
    pdf.section(
        "About this report",
        "IDkat searched the public web with AI assistance. It can miss pages, and it "
        "can't remove information for you or guarantee that sites will. This isn't "
        "legal advice. Your "
        "results were deleted from IDkat once this report was sent.",
    )
    return bytes(pdf.output())


# ============================================================================
# 5. PAGES (styled to match Medierkat and Markat)
# ============================================================================
st.markdown(
    """
    <style>
    @import url('https://fonts.googleapis.com/css2?family=Cormorant+Garamond:ital,wght@0,400;0,600;1,400&family=Inter:wght@300;400;500;600&display=swap');
    .stApp { background-color: #14120F !important; color: #F2EDE3 !important;
    font-family: 'Inter', sans-serif !important; }
    div[data-baseweb="input"], div[data-baseweb="base-input"],
    div[data-baseweb="select"] > div,
    div[data-baseweb="textarea"] { background-color: #F2EDE3 !important; border: 1px
    solid #C6BCA9 !important;
        border-radius: 2px !important; }
    div[data-baseweb="input"] input, div[data-baseweb="base-input"] input,
    div[data-baseweb="textarea"] textarea,
    textarea { background-color: #F2EDE3 !important; color: #14120F !important;
    font-weight: 600 !important;
        font-size: 0.95rem !important; opacity: 1 !important; }
    div[data-baseweb="input"] input::placeholder, textarea::placeholder { color: #5A5448
    !important; opacity: 0.8 !important; }
    div[data-baseweb="select"] * { color: #14120F !important; font-weight: 600
    !important; }
    .stButton>button, .stFormSubmitButton>button { background-color: transparent
    !important; color: #F2EDE3 !important;
        border: 1px solid #C6BCA9 !important; border-radius: 2px !important; padding:
        0.65rem 1.4rem !important;
        font-size: 0.85rem !important; letter-spacing: 0.12em !important;
        text-transform: uppercase !important; }
    .stButton>button[kind="primary"],
    .stFormSubmitButton>button[kind="primaryFormSubmit"] {
        background-color: #C6BCA9 !important; color: #14120F !important; font-weight:
        600 !important; border: none !important; }
    .metric-card { background-color: #1A1814; border: 1px solid #2C2822; padding: 18px
    12px; border-radius: 2px;
        text-align: center; min-height: 110px; display: flex; flex-direction: column;
        justify-content: center; }
    .metric-card h4 { font-size: 0.72rem; letter-spacing: 0.12em; text-transform:
    uppercase; color: #C6BCA9; margin: 0 0 6px 0; }
    .metric-card h2 { font-size: 1.25rem; font-weight: 600; color: #F2EDE3; margin: 0; }
    .disclaimer-box { background-color: #1A1814; border-left: 2px solid #C6BCA9;
    padding: 10px 14px;
        font-size: 0.8rem; color: #D9D1C2; margin-top: 20px; }
    /* Readability: brighter secondary text everywhere */
    [data-testid="stCaptionContainer"], [data-testid="stCaptionContainer"] p,
    .stCaption,
    [data-testid="stWidgetLabel"] p, [data-testid="stMarkdownContainer"] small {
        color: #D9D1C2 !important; opacity: 1 !important; }
    [data-testid="stWidgetLabel"] p { color: #F2EDE3 !important; font-weight: 500
    !important; }
    [data-testid="stExpander"] summary p, button[role="tab"] p { color: #F2EDE3
    !important; }
    [data-testid="stMarkdownContainer"] p, [data-testid="stMarkdownContainer"] li {
    color: #F2EDE3; }
    [data-testid="stSidebar"] { background-color: #1A1814 !important; }
    [data-testid="stSidebar"] * { color: #E6DFD2; }
    [data-testid="stStatusWidget"] svg { display: none !important; }
    [data-testid="stStatusWidget"]::before { content: "🦦"; font-size: 1.2rem; }
    </style>
    """,
    unsafe_allow_html=True,
)

MEERKAT_SVG = (
    '<svg width="45" height="75" viewBox="0 0 60 100" fill="#F2EDE3" '
    'xmlns="http://www.w3.org/2000/svg">'
    '<path d="M35 8c4 0 8 3 9 7 2-1 4 0 4 2s-2 4-5 4c-3 5-10 7-16 5-4-2-6-6-4-11 2-4 '
    '7-7 12-7z"/>'
    '<circle cx="40" cy="12" r="1.5" fill="#14120F"/>'
    '<path d="M28 22c2 7 2 17 1 30s-3 23-1 33c3 4 13 4 15 0-2-13-3-30-2-48 '
    '1-10-2-17-6-17z"/>'
    '<path d="M37 35c5 2 8 6 6 9-3 1-7-3-8-7z"/>'
    '<path d="M27 75C18 79 8 85 1 91c-2 2 0 3 3 1 9-6 17-11 25-13z"/>'
    '<path d="M26 81l-6 4h9zM39 81l7 4h-10z"/></svg>'
)
st.markdown(
    '<div style="display:flex;align-items:center;background-color:#1A1814;border:1px '
    "solid #2C2822;"
    'padding:24px 30px;border-radius:2px;margin-bottom:18px;">'
    f'<div style="margin-right:24px;flex-shrink:0;">{MEERKAT_SVG}</div><div>'
    '<div style="font-size:0.75rem;letter-spacing:0.25em;text-transform:uppercase;'
    "color:#C6BCA9;"
    'margin-bottom:4px;">PERSONAL PRIVACY</div>'
    "<div style=\"font-family:'Cormorant Garamond',serif;font-size:2.6rem;"
    'color:#F2EDE3;line-height:1;">IDkat</div>'
    "<div style=\"font-family:'Cormorant Garamond',serif;font-size:1.1rem;"
    "font-style:italic;color:#C6BCA9;"
    'margin-top:6px;">Find where your personal information appears online, and how to '
    "remove it.</div>"
    "</div></div>",
    unsafe_allow_html=True,
)


def metric_card(label, value):
    st.markdown(
        f"<div class='metric-card'><h4>{html.escape(label)}</h4><h2>"
        f"{html.escape(str(value))}</h2></div>",
        unsafe_allow_html=True,
    )


purge_expired()
STORE.setdefault("logins", {})
if not (app_secret() and secret("GEMINI_API_KEY")):
    st.error(
        "IDkat isn't set up yet. The administrator needs to add IDKAT_SECRET (at least "
        "32 characters) and "
        "GEMINI_API_KEY to the app's Secrets."
    )
    st.stop()

# Staying signed in after a refresh
if not st.session_state.get("user") and st.query_params.get("s"):
    if not restore_session(st.query_params.get("s")):
        st.query_params.clear()
user = st.session_state.get("user")
if user:
    touch_session()

for flag, text_ in (
    ("closed_message", "Your account has been closed and your reports deleted."),
    ("reset_message", "Your password has been reset. Please sign in."),
):
    if st.session_state.pop(flag, False):
        st.success(text_)


# ============================================================================
# SIGN IN, CREATE ACCOUNT, RESET PASSWORD
# ============================================================================
def password_problem(password, confirm):
    if len(password) < MIN_PASSWORD:
        return f"Please use at least {MIN_PASSWORD} characters for your password."
    if len(password.encode()) > 72:
        return "That password is too long. Please use 72 characters or fewer."
    if password != confirm:
        return "The passwords don't match."
    return ""


def render_admin_setup():
    """Only shown until the administrator's password hash is in Secrets."""
    with st.expander("Administrator setup: create the katadmin password"):
        st.caption(
            "Enter the password you want for katadmin. IDkat shows a line to paste "
            "into the app's Secrets. "
            "Nothing is saved here, and this helper disappears once the line is in "
            "Secrets."
        )
        with st.form("admin_setup"):
            first = st.text_input("katadmin password", type="password")
            second = st.text_input("Confirm password", type="password")
            make = st.form_submit_button("Create the Secrets line")
        if make:
            problem = password_problem(first, second)
            if problem:
                st.error(problem)
            else:
                hashed = bcrypt.hashpw(first.encode(), bcrypt.gensalt()).decode()
                st.code(f'KATADMIN_PASSWORD_HASH = "{hashed}"', language="toml")
                st.caption(
                    "Paste this line into Secrets on Streamlit Community Cloud, save, "
                    "and reboot the app."
                )


def render_sign_in():
    if not secret("KATADMIN_PASSWORD_HASH"):
        render_admin_setup()
    with st.form("sign_in"):
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        go = st.form_submit_button("Sign in", type="primary", width="stretch")
    if not go:
        return
    username = username.strip().lower()
    if not within_limit("logins", username, 5, 900):
        st.error("Too many attempts. Please wait 15 minutes and try again.")
        return
    if username == ADMIN_USERNAME:
        if check_password(password, secret("KATADMIN_PASSWORD_HASH")):
            start_session(ADMIN_USERNAME)
            st.rerun()
        st.error("Invalid username or password.")
        return
    data_key = sign_in_user(username, password)
    if data_key is None:
        st.error("Invalid username or password.")
        return
    start_session(username, data_key)
    st.rerun()


def render_sign_up():
    if not smtp_ready():
        st.info(
            "New accounts are paused while email is being set up. Please check back "
            "soon."
        )
        return
    pending = st.session_state.get("signup")
    if pending:
        st.markdown(
            f"We've emailed a 6-digit code to **{html.escape(pending['email'])}**."
        )
        with st.form("signup_code"):
            code = st.text_input("Verification code", max_chars=6)
            go = st.form_submit_button(
                "Create my account", type="primary", width="stretch"
            )
        if go:
            if not check_code("signup", code):
                st.error("That code isn't right, or it has expired.")
            elif get_user(pending["username"]):
                st.error("Sorry, that username was just taken. Please start again.")
                st.session_state.pop("signup")
            else:
                data_key, recovery = create_account(
                    pending["username"], pending["password"], pending["email"]
                )
                st.session_state.pop("signup")
                start_session(pending["username"], data_key)
                st.session_state.show_recovery = recovery
                st.rerun()
        if st.button("Start again"):
            st.session_state.pop("signup")
            st.rerun()
        return
    with st.form("signup_form"):
        username = st.text_input(
            "Choose a username",
            help="3 to 30 characters: letters, numbers, dots, dashes or "
            "underscores. Your username is the only thing IDkat's administrator can "
            "see.",
        )
        password = st.text_input(
            "Choose a password",
            type="password",
            help=f"At least {MIN_PASSWORD} characters.",
        )
        confirm = st.text_input("Confirm your password", type="password")
        email = st.text_input(
            "Your email address",
            help="Used to verify your account and reset your password. "
            "It's never stored: only a scrambled fingerprint is kept.",
        )
        with st.expander("Please read: what you're agreeing to", expanded=True):
            st.markdown(CONSENT_TEXT)
        agree_self = st.checkbox(
            "I'll use IDkat to check information about myself only"
        )
        agree_terms = st.checkbox("I agree to the terms above")
        go = st.form_submit_button(
            "Email me a verification code", type="primary", width="stretch"
        )
    if not go:
        return
    username, email = username.strip().lower(), email.strip().lower()
    problem = password_problem(password, confirm)
    if not USERNAME_RE.fullmatch(username) or username == ADMIN_USERNAME:
        st.error(
            "Please choose a different username: 3 to 30 letters, numbers, dots, "
            "dashes or underscores."
        )
    elif get_user(username):
        st.error("That username is taken. Please choose another.")
    elif problem:
        st.error(problem)
    elif not EMAIL_RE.fullmatch(email):
        st.error("Please enter a valid email address.")
    elif not (agree_self and agree_terms):
        st.error("Please tick both boxes to continue.")
    elif email_in_use(email):
        st.error(
            "There's already an account for that email address. Try signing in or "
            "resetting your password."
        )
    elif not within_limit(
        "link_requests", fingerprint(email), MAX_CODES_PER_HOUR, 3600
    ):
        st.error("Too many codes requested. Please try again in an hour.")
    else:
        try:
            send_code(email, "signup")
        except Exception:
            st.error("We couldn't send the email just now. Please try again shortly.")
            return
        st.session_state.signup = {
            "username": username,
            "password": password,
            "email": email,
        }
        st.rerun()


def render_reset():
    if not smtp_ready():
        st.info("Password resets need email, which isn't set up yet.")
        return
    pending = st.session_state.get("reset")
    if not pending:
        with st.form("reset_start"):
            username = st.text_input("Your username")
            email = st.text_input("The email address you signed up with")
            go = st.form_submit_button(
                "Email me a code", type="primary", width="stretch"
            )
        if go:
            username, email = username.strip().lower(), email.strip().lower()
            account = get_user(username)
            if not within_limit(
                "link_requests", fingerprint(email), MAX_CODES_PER_HOUR, 3600
            ):
                st.error("Too many codes requested. Please try again in an hour.")
                return
            if (
                account
                and not account["closed_at"]
                and account["email_fp"] == fingerprint(email)
            ):
                try:
                    send_code(email, "reset")
                except Exception:
                    st.error(
                        "We couldn't send the email just now. Please try again shortly."
                    )
                    return
            st.session_state.reset = {"username": username, "email": email}
            st.rerun()
        return
    st.markdown("If those details match an account, we've emailed a 6-digit code.")
    with st.form("reset_finish"):
        code = st.text_input("Verification code", max_chars=6)
        password = st.text_input("New password", type="password")
        confirm = st.text_input("Confirm new password", type="password")
        recovery = st.text_input("Your recovery code (keeps your saved reports)")
        no_code = st.checkbox(
            "I don't have my recovery code: reset anyway and delete my saved reports"
        )
        go = st.form_submit_button("Reset my password", type="primary", width="stretch")
    if st.button("Start again", key="reset_again"):
        st.session_state.pop("reset")
        st.rerun()
    if not go:
        return
    problem = password_problem(password, confirm)
    if not check_code("reset", code):
        st.error("That code isn't right, or it has expired.")
    elif problem:
        st.error(problem)
    elif not recovery.strip() and not no_code:
        st.error("Enter your recovery code, or tick the box to reset without it.")
    else:
        kept, new_code = reset_password(pending["username"], password, recovery.strip())
        if kept is None:
            st.error("That recovery code isn't right. Check it, or reset without it.")
            return
        st.session_state.pop("reset")
        if new_code:
            st.session_state.reset_recovery = new_code
        st.session_state.reset_message = True
        st.rerun()


if not user:
    if st.session_state.get("reset_recovery"):
        st.warning(
            "Your saved reports were deleted because they couldn't be unlocked. Here's "
            "your new recovery "
            "code. Save it somewhere safe: it's the only way to keep your reports if "
            "you forget your password."
        )
        st.code(st.session_state.reset_recovery)
        if st.button("I've saved it"):
            st.session_state.pop("reset_recovery")
            st.rerun()
    tab_in, tab_new, tab_reset = st.tabs(
        ["Sign in", "Create a free account", "Forgot password"]
    )
    with tab_in:
        render_sign_in()
    with tab_new:
        render_sign_up()
    with tab_reset:
        render_reset()
    st.markdown(
        "<div class='disclaimer-box'>Your reports are encrypted so only you can open "
        "them. IDkat's "
        "administrator sees only your username and how often you use IDkat.</div>",
        unsafe_allow_html=True,
    )
    st.stop()


# ============================================================================
# ADMIN CONSOLE (katadmin): usernames and usage only, never names, searches or reports
# ============================================================================
def usage_frames():
    users = pd.DataFrame(
        db_rows("SELECT username, created_at, closed_at, last_active FROM idk_users"),
        columns=["username", "created_at", "closed_at", "last_active"],
    )
    sessions = pd.DataFrame(
        db_rows(
            "SELECT username, started_at, last_seen FROM idk_sessions WHERE username "
            "!= :a",
            a=ADMIN_USERNAME,
        ),
        columns=["username", "started_at", "last_seen"],
    )
    events = pd.DataFrame(
        db_rows("SELECT username, kind, at FROM idk_events"),
        columns=["username", "kind", "at"],
    )
    return users, sessions, events


def render_admin():
    top1, top2 = st.columns([3, 1])
    top1.markdown(f"Signed in as **{ADMIN_USERNAME}** · administrator")
    if top2.button("Sign out", width="stretch"):
        end_session()
        st.rerun()
    if DB["local"]:
        st.warning(
            "No permanent database is connected, so accounts and reports will be lost "
            "when the app restarts. "
            "Add the Supabase connection to Secrets (see the README)."
        )
    users, sessions, events = usage_frames()
    now = time.time()
    active = users[users["closed_at"].isna()] if not users.empty else users
    if not sessions.empty:
        sessions["minutes"] = (
            (sessions["last_seen"] - sessions["started_at"]) / 60
        ).clip(lower=0)
        stamps = pd.to_datetime(
            sessions["started_at"], unit="s", utc=True
        ).dt.tz_convert(TZ)
        sessions["hour"], sessions["weekday"] = stamps.dt.hour, stamps.dt.day_name()
        sessions["day"] = stamps.dt.date

    def recent(frame, column, days):
        return frame[frame[column] > now - days * 86400] if not frame.empty else frame

    tab_overview, tab_users, tab_ads, tab_sponsors = st.tabs(
        ["📊 Overview", "👥 Users", "📣 For advertisers", "🏷️ Sponsors"]
    )
    with tab_overview:
        c1, c2, c3, c4 = st.columns(4)
        with c1:
            metric_card("Active accounts", len(active))
        with c2:
            metric_card(
                "Active users (7 days)",
                (
                    recent(sessions, "last_seen", 7)["username"].nunique()
                    if not sessions.empty
                    else 0
                ),
            )
        with c3:
            metric_card(
                "Searches (30 days)",
                (
                    len(recent(events[events["kind"] == "search_started"], "at", 30))
                    if not events.empty
                    else 0
                ),
            )
        with c4:
            metric_card(
                "Reports saved (30 days)",
                (
                    len(recent(events[events["kind"] == "report_saved"], "at", 30))
                    if not events.empty
                    else 0
                ),
            )
        if not sessions.empty:
            st.markdown("##### Sessions by hour of day")
            st.bar_chart(
                sessions.groupby("hour").size().reindex(range(24), fill_value=0)
            )
            st.markdown("##### Sessions by day of week")
            days = [
                "Monday",
                "Tuesday",
                "Wednesday",
                "Thursday",
                "Friday",
                "Saturday",
                "Sunday",
            ]
            st.bar_chart(sessions.groupby("weekday").size().reindex(days, fill_value=0))
        if not users.empty:
            st.markdown("##### New accounts by week")
            weeks = (
                pd.to_datetime(users["created_at"], unit="s", utc=True)
                .dt.tz_convert(TZ)
                .dt.tz_localize(None)
                .dt.to_period("W")
            )
            st.bar_chart(users.groupby(weeks.astype(str)).size())
        st.caption(f"Times shown in {TZ.key}.")

    with tab_users:
        rows = []
        for u in users.to_dict("records"):
            mine = (
                sessions[sessions["username"] == u["username"]]
                if not sessions.empty
                else sessions
            )
            evs = (
                events[events["username"] == u["username"]]
                if not events.empty
                else events
            )
            rows.append(
                {
                    "Username": u["username"],
                    "Account opened": local_time(u["created_at"]),
                    "Account closed": (
                        local_time(u["closed_at"])
                        if u["closed_at"] == u["closed_at"]
                        else ""
                    ),
                    "Sessions": len(mine),
                    "Total time (min)": (
                        round(float(mine["minutes"].sum()), 1) if len(mine) else 0
                    ),
                    "Searches": (
                        int((evs["kind"] == "search_started").sum()) if len(evs) else 0
                    ),
                    "Reports saved": (
                        int((evs["kind"] == "report_saved").sum()) if len(evs) else 0
                    ),
                    "Last active": local_time(u["last_active"]),
                }
            )
        table = pd.DataFrame(rows)
        st.dataframe(table, hide_index=True, width="stretch")
        st.caption(
            "Only usernames and usage are recorded. Names, searches, answers and "
            "reports are never visible "
            "here: reports are encrypted with each user's own key."
        )
        if rows:
            st.download_button(
                "Download users table (CSV)",
                table.to_csv(index=False),
                "idkat_users.csv",
                "text/csv",
            )
        if not sessions.empty:
            st.markdown("##### Recent sessions")
            recent_sessions = sessions.sort_values("started_at", ascending=False).head(
                50
            )
            st.dataframe(
                pd.DataFrame(
                    {
                        "Username": recent_sessions["username"],
                        "Started": recent_sessions["started_at"].map(local_time),
                        "Length (min)": recent_sessions["minutes"].round(1),
                    }
                ),
                hide_index=True,
                width="stretch",
            )

    with tab_ads:
        st.caption(
            "Combined statistics only: no usernames or individual records. Safe to "
            "share with sponsors."
        )
        summary = [("Active accounts", len(active))]
        if not sessions.empty:
            for days in (7, 30):
                summary.append(
                    (
                        f"Active users, last {days} days",
                        recent(sessions, "last_seen", days)["username"].nunique(),
                    )
                )
            per_user = sessions.groupby("username").size()
            returning = sessions.groupby("username")["day"].nunique()
            summary += [
                ("Sessions, last 30 days", len(recent(sessions, "started_at", 30))),
                ("Average sessions per user", round(float(per_user.mean()), 1)),
                (
                    "Median session length (min)",
                    round(float(sessions["minutes"].median()), 1),
                ),
                (
                    "Returning users (used IDkat on 2+ days)",
                    f"{round(100 * float((returning >= 2).mean()))}%",
                ),
                (
                    "Busiest hour",
                    f"{int(sessions.groupby('hour').size().idxmax()):02d}:00",
                ),
                ("Busiest day", sessions.groupby("weekday").size().idxmax()),
            ]
        if not events.empty:
            summary += [
                (
                    "Searches, last 30 days",
                    len(recent(events[events["kind"] == "search_started"], "at", 30)),
                ),
                (
                    "Reports saved, last 30 days",
                    len(recent(events[events["kind"] == "report_saved"], "at", 30)),
                ),
            ]
        audience = pd.DataFrame(
            [(m, str(v)) for m, v in summary], columns=["Measure", "Value"]
        )
        st.dataframe(audience, hide_index=True, width="stretch")
        sponsors = db_rows(
            "SELECT name, impressions, clicks, active FROM idk_sponsors ORDER BY "
            "created_at"
        )
        if sponsors:
            st.markdown("##### Sponsor performance")
            perf = pd.DataFrame(
                [
                    {
                        "Sponsor": s["name"],
                        "Views": s["impressions"],
                        "Clicks": s["clicks"],
                        "Click rate": (
                            f"{round(100 * s['clicks'] / s['impressions'], 1)}%"
                            if s["impressions"]
                            else "-"
                        ),
                        "Status": "Active" if s["active"] else "Paused",
                    }
                    for s in sponsors
                ]
            )
            st.dataframe(perf, hide_index=True, width="stretch")
            audience = pd.concat(
                [
                    audience,
                    pd.DataFrame(
                        [
                            (
                                f"{s['name']}: views / clicks",
                                f"{s['impressions']} / {s['clicks']}",
                            )
                            for s in sponsors
                        ],
                        columns=["Measure", "Value"],
                    ),
                ]
            )
        st.download_button(
            "Download audience summary (CSV)",
            audience.to_csv(index=False),
            "idkat_audience_summary.csv",
            "text/csv",
        )

    with tab_sponsors:
        st.caption(
            "Sponsored cards are shown to users as plain text and images, clearly "
            "labelled 'Sponsored'. "
            "No tracking scripts or cookies: views and clicks are counted inside IDkat "
            "only."
        )
        with st.form("new_sponsor", clear_on_submit=True):
            name = st.text_input("Sponsor name")
            headline = st.text_input("Headline")
            body = st.text_area("Short message", max_chars=200)
            link = st.text_input(
                "Link (https://...)",
                help="An affiliate link is fine, as long as it doesn't include "
                "anything about the user.",
            )
            image = st.file_uploader(
                "Image (optional, PNG or JPEG, up to 300 KB)",
                type=["png", "jpg", "jpeg"],
            )
            add = st.form_submit_button("Add sponsor", type="primary")
        if add:
            if not name.strip() or not link.startswith("https://"):
                st.error("Please give a name and a link starting with https://")
            elif image is not None and len(image.getvalue()) > 300_000:
                st.error("Please use an image under 300 KB.")
            else:
                stored = ""
                if image is not None:
                    mime = (
                        "image/png"
                        if image.name.lower().endswith(".png")
                        else "image/jpeg"
                    )
                    stored = f"{mime};{b64encode(image.getvalue()).decode()}"
                db_run(
                    """INSERT INTO idk_sponsors (id, name, headline, body, link, image,
                    active, impressions,
                          clicks, created_at) VALUES (:id, :n, :h, :b, :l, :i, 1, 0, 0,
                          :t)""",
                    id=uuid.uuid4().hex,
                    n=name.strip(),
                    h=headline.strip(),
                    b=body.strip(),
                    l=link.strip(),
                    i=stored,
                    t=time.time(),
                )
                st.success(f"Added {name.strip()}.")
        for s in db_rows("SELECT * FROM idk_sponsors ORDER BY created_at"):
            with st.expander(
                f"{'🟢' if s['active'] else '⏸️'} {s['name']} · {s['impressions']} "
                f"views · {s['clicks']} clicks"
            ):
                st.markdown(
                    f"**{html.escape(s['headline'] or '')}**  "
                    f"\n{html.escape(s['body'] or '')}  \n{html.escape(s['link'])}"
                )
                b1, b2 = st.columns(2)
                if b1.button(
                    "Pause" if s["active"] else "Activate", key=f"toggle_{s['id']}"
                ):
                    db_run(
                        "UPDATE idk_sponsors SET active = :a WHERE id = :id",
                        a=0 if s["active"] else 1,
                        id=s["id"],
                    )
                    st.rerun()
                if b2.button("Delete", key=f"delete_{s['id']}"):
                    db_run("DELETE FROM idk_sponsors WHERE id = :id", id=s["id"])
                    st.rerun()


if user == ADMIN_USERNAME:
    render_admin()
    st.stop()


# ============================================================================
# USER AREA: search, library and account
# ============================================================================
data_key = st.session_state.get("data_key")
clues = st.session_state.setdefault("clues", {})
not_me = st.session_state.setdefault("not_me", set())

if st.session_state.get("_goto"):
    st.session_state.nav = st.session_state.pop("_goto")

with st.sidebar:
    st.markdown(f"Signed in as **{html.escape(user)}**")
    page = st.radio(
        "Go to",
        ["🔎 Search", "📚 My library", "⚙️ Account"],
        key="nav",
        label_visibility="collapsed",
    )
    if st.button("Sign out", width="stretch"):
        end_session()
        st.rerun()
    st.divider()
    render_sponsor()

if st.session_state.get("show_recovery"):
    st.warning(
        "**Save your recovery code now.** It's the only way to keep your saved reports "
        "if you forget your "
        "password. IDkat can't show it again or recover it for you."
    )
    st.code(st.session_state.show_recovery)
    if st.button("I've saved my recovery code"):
        st.session_state.pop("show_recovery")
        st.rerun()

if st.session_state.pop("saved_message", False):
    st.success(
        "Your report is saved in your library, and your search results have been "
        "deleted."
    )


PRIVATE_NOTE = (
    "🔒 Your answers stay on this page. They're compared with the results inside IDkat "
    "itself: "
    "they're never sent to search engines, AI services or anyone else, and they're "
    "deleted with "
    "your results."
)


def about_you_fields(prefix, kinds):
    """Neutral questions about you. They never reveal anything a page says about someone else."""
    answers = {
        kind: st.text_input(
            QUESTIONS[kind],
            value=", ".join(clues.get(kind, [])),
            key=f"{prefix}_{kind}",
        )
        for kind in kinds
        if kind in QUESTIONS
    }
    public = description = None
    if "Public" in kinds:
        current = clues.get("Public", "")
        public = st.radio(
            "Are you a public figure in any way?",
            PUBLIC_OPTIONS,
            key=f"{prefix}_public",
            index=next((i for i, o in enumerate(PUBLIC_OPTIONS) if o == current), 0),
        )
        description = st.text_input(
            "If so, briefly how (e.g. university spokesperson, local councillor)",
            value=", ".join(clues.get("Public description", [])),
            key=f"{prefix}_publicdesc",
        )
    links = st.text_input(
        "Links to your own profiles or website (optional)",
        value=", ".join(clues.get("Links", [])),
        key=f"{prefix}_links",
    )
    return answers, public, description, links


def save_answers(answers, public, description, links):
    for kind, value in answers.items():
        clues[kind] = split_answers(value)
    if public is not None:
        clues["Public"] = public
        clues["Public description"] = split_answers(description)
    clues["Links"] = [u for u in split_answers(links) if is_url(u)]


ALL_ASKS = [
    "Occupation",
    "Interest",
    "Public",
    "Place",
    "Workplace",
    "Education",
    "Username",
]


def question_form(kinds, key, heading, button):
    with st.form(key):
        st.markdown(heading)
        st.caption(PRIVATE_NOTE)
        fields = about_you_fields(key, kinds)
        submitted = st.form_submit_button(button, type="primary", width="stretch")
    if submitted:
        save_answers(*fields)
        st.rerun()


def considered(items):
    return [i for i in items if i.get("key") not in not_me]


def tally(items):
    verified, others, unverified, questions = sort_out(considered(items), clues)
    others += sum(1 for i in items if i.get("key") in not_me)
    line = (
        f"**{len(verified)}** confirmed as yours · **{others}** about other people · "
        f"**{unverified}** not yet confirmed"
    )
    return verified, others, unverified, questions, line


def render_search():
    job = my_job(user)

    @st.fragment(run_every=3)
    def progress_panel():
        current = my_job(user)
        if current and current["status"] != "running":
            st.rerun(scope="app")
        if current:
            *_, line = tally(current["items"])
            st.info(
                f"⏳ {current['progress']} ({int(time.time() - current['started'])}s)  "
                f"\nSo far: {line}  \n"
                "You can leave this page and come back: your results are kept for "
                f"{RESULTS_HOURS} hours, or until you save your report."
            )

    if job and job["status"] == "running":
        progress_panel()
        question_form(
            ALL_ASKS,
            "q_live",
            "#### While you wait: help us rule out other people with your name",
            "Update my answers",
        )
        return
    if job and job["status"] == "failed":
        st.error(job["error"])
        delete_my_results(user)
        job = None
    if job and job["status"] == "done":
        render_results(job)
        return
    render_search_form()


def render_results(job):
    verified, others, unverified, questions, line = tally(job["items"])
    left = RESULTS_HOURS * 60 - int((time.time() - job["started"]) / 60)
    st.subheader(f"Your results: {exposure_level(verified)} exposure")
    st.markdown(line)
    if job.get("refine_error"):
        st.warning(job.pop("refine_error"))
    if job.get("last_added") is not None:
        added = job.pop("last_added")
        st.success(
            f"The extra search found {added} new page{'s' if added != 1 else ''}."
            if added
            else "The extra search found no new pages."
        )
    if questions:
        question_form(
            questions,
            "q_more",
            f"#### Answer to check {unverified} more "
            f"page{'s' if unverified != 1 else ''}",
            "Check these pages",
        )
    c1, c2, c3 = st.columns(3)
    with c1:
        metric_card("Confirmed as yours", len(verified))
    with c2:
        metric_card(
            "Sensitive details",
            sum(1 for i in verified if HIGH_TYPES & set(i["exposed"])),
        )
    with c3:
        metric_card("Quick fixes", sum(1 for i in verified if i["effort"] == "Quick"))
    if verified:
        st.caption(
            "These pages matched your answers. Open any you're unsure about, and mark "
            "it 'Not me' if it isn't "
            "you: it will be left out of your report."
        )
    for i in verified:
        icon = "🔴" if HIGH_TYPES & set(i["exposed"]) else "🟠"
        with st.expander(f"{icon} {i['site']} · {i['page_type']}"):
            st.markdown(f"**Exposes:** {html.escape(', '.join(i['exposed']).lower())}")
            st.markdown(
                f"**What to do ({i['effort'].lower()}):** {html.escape(i['removal'])}"
            )
            if i["url"]:
                st.markdown(f"[Open the page]({i['url']})")
            if i["removal_link"]:
                st.markdown(f"[Opt-out or settings page]({i['removal_link']})")
            if st.button("Not me: leave this out", key=f"notme_{i['key']}"):
                not_me.add(i["key"])
                st.rerun()
    if left_out_text(others, unverified):
        st.caption(
            left_out_text(others, unverified)
            + " IDkat only shows and reports pages it can confirm as yours."
        )
    if job.get("breaches"):
        st.warning(
            f"Your email appears in {len(job['breaches'])} known data breach(es). "
            "Details are in your report."
        )
    if job.get("refines", 0) < MAX_REFINES:
        with st.expander("🔎 Search again with more details"):
            with st.form("refine"):
                extra = st.text_input(
                    "Other names, usernames or terms to search for",
                    placeholder="e.g. a former surname, an old username, a club you "
                    "belonged to",
                )
                st.caption(
                    "These are sent to the search, like your name. Any new pages are "
                    "added to your results "
                    f"without duplicates. {MAX_REFINES - job.get('refines', 0)} extra "
                    "search(es) left."
                )
                again = st.form_submit_button(
                    "Search again", type="primary", width="stretch"
                )
            if again and extra.strip():
                start_refine(job, extra.strip()[:200])
                st.rerun()

    st.divider()
    st.markdown(
        "Save your one-page summary and full action plan to your library. Only pages "
        "confirmed as yours are "
        "included, and the report is encrypted so only you can open it. **Your search "
        "results and answers "
        "are then deleted.** If you do nothing, they're deleted automatically in "
        f"about {max(left, 1)} minutes."
    )
    with st.form("save_report"):
        copy_to = st.text_input(
            "Also email me a copy (optional)",
            placeholder="your@email.com",
            help="Used once to send the copy, then forgotten. Leave blank to skip.",
        )
        save = st.form_submit_button(
            "💾 Save my report", type="primary", width="stretch"
        )
    if save:
        copy_to = copy_to.strip().lower()
        if copy_to and not EMAIL_RE.fullmatch(copy_to):
            st.error("Please enter a valid email address, or leave it blank.")
            return
        report = {
            "verified": verified,
            "others": others,
            "unverified": unverified,
            "breaches": job.get("breaches"),
            "name": job["name"],
            "finished": job["finished"],
        }
        with st.spinner("Preparing your report"):
            summary, full = summary_pdf(report), full_pdf(report)
            save_report(
                user,
                data_key,
                f"{job['name']} · {local_time(time.time(), '%d %b %Y %H:%M')}",
                summary,
                full,
            )
        if copy_to and smtp_ready():
            try:
                send_email(
                    copy_to,
                    "Your IDkat report",
                    "Attached is your IDkat report: a one-page summary and a "
                    "full action plan. A copy is saved in your IDkat library.\n",
                    [("IDkat_summary.pdf", summary), ("IDkat_full_report.pdf", full)],
                )
            except Exception:
                st.warning("Your report is saved, but the email copy couldn't be sent.")
        delete_my_results(user)
        not_me.clear()
        st.session_state.saved_message = True
        st.session_state["_goto"] = "📚 My library"
        st.rerun()
    if st.button("🗑️ Delete my results without saving", width="stretch"):
        delete_my_results(user)
        not_me.clear()
        st.rerun()


def render_search_form():
    st.subheader("Search for your information")
    st.caption(
        "IDkat only searches for you. For your protection, the name you search is "
        "locked to your account "
        f"for {NAME_LOCK_DAYS} days."
    )
    with st.form("scan"):
        st.markdown("**Used for the search**")
        name = st.text_input("Your full name")
        aka = st.text_input(
            "Other names you're known by (optional)",
            placeholder="e.g. maiden name, nickname",
        )
        location = st.text_input(
            "Your city or region (optional, helps rule out other people)"
        )
        channels = st.multiselect(
            "Where to look", list(CHANNELS), default=list(CHANNELS)
        )
        include_email = st.checkbox(
            "Also check where my email address appears, and for data breaches",
            value=False,
            help="Sends the email address below to Google's search AI and, if set up, "
            "to the Have I Been Pwned "
            "breach service. It isn't stored.",
        )
        check_email = st.text_input("Email address to check (only if ticked above)")
        st.markdown(
            "**About you, to rule out other people with your name** (optional, and you "
            "can add these later)"
        )
        st.caption(PRIVATE_NOTE)
        start_fields = about_you_fields("start", ALL_ASKS)
        focus_work = st.checkbox(
            "Also use my occupation to focus the search",
            value=False,
            help="Finds more of the right pages, but sends your occupation to Google's "
            "search AI along with your name.",
        )
        confirm = st.checkbox(
            "I confirm this is my own name, and I'm searching for information about "
            "myself"
        )
        go = st.form_submit_button("Start search", type="primary", width="stretch")
    if not go:
        return
    save_answers(*start_fields)
    clean_name = re.sub(r"\s+", " ", name).strip()
    check_email = check_email.strip().lower()
    lock = name_lock(user)
    if not clean_name or not channels:
        st.error("Please enter your name and choose at least one place to look.")
    elif not confirm:
        st.error("Please confirm you're searching for yourself.")
    elif include_email and not EMAIL_RE.fullmatch(check_email):
        st.error("Please enter the email address to check, or untick that option.")
    elif lock and lock != fingerprint(clean_name):
        st.error(
            "Your account is already linked to a different name. IDkat only lets you "
            "search for yourself."
        )
    elif not within_limit("scans", fingerprint(user), MAX_SCANS_PER_DAY, 86400):
        st.error(
            f"You can run up to {MAX_SCANS_PER_DAY} searches a day. Please try again "
            "tomorrow."
        )
    elif not within_limit(
        "daily_total", "all", int(secret("DAILY_SCAN_CAP", 50)), 86400
    ):
        st.error("IDkat has reached today's limit. Please try again tomorrow.")
    else:
        set_name_lock(user, clean_name)
        not_me.clear()
        occupation = ", ".join(clues.get("Occupation", [])) if focus_work else ""
        log_event(user, "search_started")
        start_scan(
            user,
            {
                "name": clean_name,
                "aka": aka.strip(),
                "location": location.strip(),
                "email": check_email if include_email else "",
                "include_email": include_email,
                "occupation": occupation,
            },
            channels,
        )
        st.rerun()


def render_library():
    st.subheader("My library")
    st.caption(
        "Your reports are encrypted with your own key. Only you can open them: not "
        "IDkat's administrator, "
        "and not anyone with access to its database."
    )
    if data_key is None:
        st.warning("Please sign out and sign in again to open your library.")
        return
    reports = list_reports(user, data_key)
    if not reports:
        st.info(
            "No saved reports yet. Run a search and save your report to keep it here."
        )
    for r in reports:
        with st.expander(f"📄 {r['title']}"):
            st.caption(f"Saved {local_time(r['created_at'])}")
            c1, c2, c3 = st.columns(3)
            c1.download_button(
                "One-page summary",
                open_report(user, data_key, r["id"], "summary_pdf"),
                f"IDkat_summary_{local_time(r['created_at'], '%Y%m%d')}.pdf",
                "application/pdf",
                key=f"sum_{r['id']}",
            )
            c2.download_button(
                "Full action plan",
                open_report(user, data_key, r["id"], "full_pdf"),
                f"IDkat_full_report_{local_time(r['created_at'], '%Y%m%d')}.pdf",
                "application/pdf",
                key=f"full_{r['id']}",
            )
            if c3.button("Delete", key=f"del_{r['id']}"):
                delete_report(user, r["id"])
                st.rerun()


def render_account():
    st.subheader("Account")
    with st.form("change_password", clear_on_submit=True):
        st.markdown("**Change your password**")
        current = st.text_input("Current password", type="password")
        new = st.text_input("New password", type="password")
        confirm = st.text_input("Confirm new password", type="password")
        change = st.form_submit_button("Change password", type="primary")
    if change:
        key = sign_in_user(user, current)
        problem = password_problem(new, confirm)
        if key is None:
            st.error("Your current password isn't right.")
        elif problem:
            st.error(problem)
        else:
            set_password(user, key, new)
            log_event(user, "password_changed")
            st.success("Password changed. Your saved reports are unchanged.")
    st.divider()
    st.markdown("**Recovery code**")
    st.caption("Lost your recovery code? Make a new one. The old one stops working.")
    if st.button("Make a new recovery code") and data_key is not None:
        st.session_state.show_recovery = replace_recovery_code(user, data_key)
        st.rerun()
    st.divider()
    st.markdown("**Close your account**")
    st.caption(
        "Deletes your saved reports, password and keys straight away. IDkat keeps only "
        "your username, "
        "the dates your account was open and simple usage counts."
    )
    sure = st.checkbox("I understand my reports will be permanently deleted")
    if st.button("Close my account", disabled=not sure):
        close_account(user)
        delete_my_results(user)
        end_session()
        st.session_state.closed_message = True
        st.rerun()


if page == "🔎 Search":
    render_search()
elif page == "📚 My library":
    render_library()
else:
    render_account()
