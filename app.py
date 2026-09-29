"""
IDkat: find and fix your personal information online.

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
from base64 import urlsafe_b64decode, urlsafe_b64encode
from email.message import EmailMessage
from pathlib import Path
from urllib.parse import urlparse

import matplotlib
import requests
import streamlit as st
from fpdf import FPDF
from google import genai
from google.genai import types
from pydantic import BaseModel, Field

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
INK, BONE, SAND, MUTED = "#14120F", "#F2EDE3", "#C6BCA9", "#8A8275"

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
# 2. PASSWORDLESS SIGN-IN
# ============================================================================
def _b64(text):
    return urlsafe_b64encode(text.encode()).decode().rstrip("=")


def _unb64(text):
    return urlsafe_b64decode(text + "=" * (-len(text) % 4)).decode()


def _sign(body):
    return hmac.new(app_secret(), body.encode(), "sha256").hexdigest()[:32]


def make_token(email, minutes, kind):
    body = (
        f"{kind}|{email}|{int(time.time()) + minutes * 60}|{pysecrets.token_urlsafe(8)}"
    )
    return f"{_b64(body)}.{_sign(body)}"


def read_token(token, kind, single_use=False):
    try:
        encoded, sig = str(token).split(".")
        body = _unb64(encoded)
        token_kind, email, expiry, nonce = body.split("|")
        expiry = int(expiry)
    except (ValueError, UnicodeDecodeError):
        return None
    if not app_secret() or token_kind != kind or expiry < time.time():
        return None
    if not hmac.compare_digest(sig, _sign(body)):
        return None
    if single_use:
        with STORE["lock"]:
            if nonce in STORE["used_links"]:
                return None
            STORE["used_links"][nonce] = expiry
    return email


def smtp_ready():
    return all(secret(k) for k in ("SMTP_HOST", "SMTP_USER", "SMTP_PASSWORD"))


def send_email(to, subject, text, attachments=()):
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = str(secret("SMTP_FROM", secret("SMTP_USER")))
    msg["To"] = to
    msg.set_content(text)
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


CONSENT_TEXT = (
    "By signing in, you confirm that:\n"
    "- you are using IDkat to check information about yourself, not anyone else;\n"
    "- your name, the details you enter and your email address will be used to search "
    "the public web, "
    "processed by Google's Gemini AI service;\n"
    "- IDkat shows where your information appears and how to remove it. It does not "
    "remove anything for you, "
    "and it can't guarantee that every page is found or that sites will agree to "
    "remove information;\n"
    "- your results are deleted as soon as your reports are emailed to you, or after "
    f"{RESULTS_HOURS} hours, whichever comes first. To prevent misuse, IDkat keeps "
    "only a scrambled "
    "fingerprint of your email address and the name you search, for up to "
    f"{NAME_LOCK_DAYS} days."
)


def sign_in_link(email):
    base = str(secret("APP_URL", "")).rstrip("/")
    return f"{base}/?t={make_token(email, LINK_MINUTES, 'link')}"


def email_sign_in_link(email):
    send_email(
        email,
        "Your IDkat sign-in link",
        "Hello,\n\nHere's your link to sign in to IDkat. It works once, for "
        f"{LINK_MINUTES} minutes:\n\n"
        f"{sign_in_link(email)}\n\n{CONSENT_TEXT}\n\nIf you didn't ask for this, you "
        "can ignore this email.\n",
    )


def signed_in_email():
    return st.session_state.get("email")


def sign_out():
    for key in list(st.session_state.keys()):
        del st.session_state[key]
    st.query_params.clear()


# ============================================================================
# 3. SEARCH ENGINE (runs in the background; no Streamlit calls inside)
# ============================================================================
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
    match: str = Field(
        default="Possibly you",
        description="'Likely you', 'Possibly you' or 'Probably someone else'.",
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
    return f"""Today is {datetime.date.today():%d %B %Y}.
You are helping a person find where their OWN personal information appears on the public
web, so they can
remove it. They have signed in with a verified email and confirmed they are searching
for themselves.
Person: "{profile['name']}".{aka}{where}{email}
Focus this search on: {focus}.
For each page found, report: the site, the page URL, what KINDS of personal information
it exposes (for
example home address, phone number, email, date of birth or age, photos, workplace,
relatives, usernames),
whether it is likely this person or possibly someone else with the same name, and how
the person could get
it removed or hidden, including any opt-out or privacy-settings page.
Describe only the TYPES of information exposed. Never repeat the actual address, phone
number, email, date
of birth or other values. Report only what the search results show."""


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
3. match: 'Likely you', 'Possibly you' or 'Probably someone else', based on the details
given.
4. removal: practical steps in one or two sentences. effort: Quick, Moderate or Hard.
5. Never include actual addresses, phone numbers, email addresses, dates of birth or ID
numbers anywhere.

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


def exposure_level(items):
    mine = [i for i in items if i["match"] != "Probably someone else"]
    high = [i for i in mine if HIGH_TYPES & set(i["exposed"])]
    if len(high) >= 2 or any(i["match"] == "Likely you" for i in high):
        return "High"
    if high or len(mine) >= 3:
        return "Moderate"
    return "Low" if mine else "Minimal"


def sort_key(item):
    high = bool(HIGH_TYPES & set(item["exposed"]))
    return (MATCHES.index(item["match"]), not high, EFFORTS.index(item["effort"]))


def run_scan(job, profile, channels, api_key, model):
    """The background search. Results are held in memory only."""
    try:
        client = model_client(api_key)
        groups = [
            channels[: (len(channels) + 1) // 2],
            channels[(len(channels) + 1) // 2 :],
        ]
        items, seen = [], set()
        for n, group in enumerate([g for g in groups if g], 1):
            job["progress"] = (
                f"Search {n} of {len([g for g in groups if g])}: "
                f"{', '.join(group).lower()}"
            )
            resp = generate(
                client,
                model,
                search_prompt(profile, "; ".join(CHANNELS[c] for c in group)),
                search=True,
            )
            sources = []
            for cand in getattr(resp, "candidates", None) or []:
                meta = getattr(cand, "grounding_metadata", None)
                for chunk in (
                    (getattr(meta, "grounding_chunks", None) or []) if meta else []
                ):
                    web = getattr(chunk, "web", None)
                    if web and getattr(web, "uri", None):
                        final = resolve_redirect(web.uri)
                        if final:
                            sources.append((getattr(web, "title", "") or "", final))
            allowed = {norm_url(u) for _, u in sources}
            notes = resp.text or ""
            if not notes.strip():
                continue
            job["progress"] = f"Reading results ({n})"
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
                    re.sub(r"^```(?:json)?\s*|\s*```$", "", (data.text or "").strip())
                    or "{}"
                )
            )
            for e in raw.get("exposures", []):
                item = {
                    "site": scrub(e.get("site"))[:80] or "Unknown site",
                    "page_type": pick(e.get("page_type"), PAGE_TYPES, "Other"),
                    "exposed": [
                        t
                        for t in (
                            pick(x, EXPOSED_TYPES, "Other")
                            for x in e.get("exposed", [])
                        )
                        if t
                    ][:8]
                    or ["Other"],
                    "match": pick(e.get("match"), MATCHES, "Possibly you"),
                    "removal": scrub(e.get("removal"))[:400],
                    "effort": pick(e.get("effort"), EFFORTS, "Moderate"),
                    "url": (
                        e.get("source_url")
                        if norm_url(e.get("source_url")) in allowed
                        else ""
                    ),
                    "removal_link": (
                        e.get("removal_link")
                        if norm_url(e.get("removal_link")) in allowed
                        else ""
                    ),
                }
                item["exposed"] = list(dict.fromkeys(item["exposed"]))
                key = (
                    norm_url(item["url"])
                    or f"{item['site'].lower()}|{item['page_type']}"
                )
                if key not in seen:
                    seen.add(key)
                    items.append(item)
        job["progress"] = (
            "Checking data breaches" if secret("HIBP_API_KEY") else "Finishing"
        )
        breaches = hibp_breaches(profile["email"]) if profile["include_email"] else None
        items.sort(key=sort_key)
        job["result"] = {
            "items": items,
            "breaches": breaches,
            "level": exposure_level(items),
            "name": profile["name"],
            "finished": datetime.datetime.now().strftime("%d %b %Y %H:%M"),
        }
        job["status"] = "done"
        if smtp_ready() and secret("APP_URL"):
            try:
                send_email(
                    profile["email"],
                    "Your IDkat results are ready",
                    "Your IDkat search has finished. Sign in to review your results "
                    "and get your reports "
                    f"(this link works once, for {LINK_MINUTES} "
                    f"minutes):\n\n{sign_in_link(profile['email'])}\n\n"
                    f"Your results will be deleted in {RESULTS_HOURS} hours if you "
                    "don't get your reports "
                    "before then.\n",
                )
            except Exception:
                pass
    except Exception as exc:
        job["status"], job["error"] = (
            "failed",
            f"The search couldn't be completed: {str(exc)[:300]}",
        )


def start_scan(email, profile, channels):
    job = {
        "id": uuid.uuid4().hex[:12],
        "owner": fingerprint(email),
        "status": "running",
        "progress": "Starting",
        "started": time.time(),
        "result": None,
        "error": "",
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
        self.set_font(FONT, "", 6.5)
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
        self.rect(0, 0, self.w, 32, "F")
        self.set_xy(16, 8)
        self.set_font(FONT, "B", 7.5)
        self.set_text_color(*hex_rgb(SAND))
        self.cell(0, 4, "IDKAT · YOUR ONLINE FOOTPRINT", new_x="LMARGIN", new_y="NEXT")
        self.set_font(FONT, "B", 15)
        self.set_text_color(*hex_rgb(BONE))
        self.cell(0, 8, pdf_text(title), new_x="LMARGIN", new_y="NEXT")
        self.set_font(FONT, "I", 8)
        self.set_text_color(*hex_rgb(SAND))
        self.cell(0, 5, pdf_text(subtitle), new_x="LMARGIN", new_y="NEXT")
        self.set_y(38)

    def cards(self, cards):
        gap, height = 3, 18
        width = (self.epw - gap * (len(cards) - 1)) / len(cards)
        top = self.get_y()
        for i, (label, value) in enumerate(cards):
            x = self.l_margin + i * (width + gap)
            self.set_fill_color(*hex_rgb(BONE))
            self.set_draw_color(*hex_rgb(SAND))
            self.rect(x, top, width, height, "DF")
            self.set_xy(x, top + 3)
            self.set_font(FONT, "B", 6.5)
            self.set_text_color(*hex_rgb(MUTED))
            self.cell(width, 4, pdf_text(label.upper()), align="C")
            self.set_xy(x, top + 8)
            self.set_font(FONT, "B", 12)
            self.set_text_color(*hex_rgb(INK))
            self.cell(width, 6, pdf_text(value), align="C")
        self.set_xy(self.l_margin, top + height + 5)

    def section(self, title, body=""):
        if self.get_y() > self.page_break_trigger - 18:
            self.add_page()
        self.set_font(FONT, "B", 10.5)
        self.set_text_color(*hex_rgb(INK))
        self.cell(self.epw, 6, pdf_text(title), new_x="LMARGIN", new_y="NEXT")
        if body:
            self.set_font(FONT, "", 8.5)
            self.set_text_color(40, 40, 40)
            self.multi_cell(self.epw, 4.2, pdf_text(body))
        self.ln(2)

    def item(self, colour, heading, lines):
        if self.get_y() > self.page_break_trigger - 14:
            self.add_page()
        y = self.get_y()
        self.set_fill_color(*hex_rgb(colour))
        self.rect(self.l_margin, y + 1, 2.4, 2.4, "F")
        self.set_x(self.l_margin + 4)
        self.set_font(FONT, "B", 8.5)
        self.set_text_color(*hex_rgb(INK))
        self.multi_cell(self.epw - 4, 4, pdf_text(heading))
        for style, text in lines:
            self.set_x(self.l_margin + 4)
            self.set_font(FONT, style, 7.5)
            self.set_text_color(60, 60, 60)
            self.multi_cell(self.epw - 4, 3.6, pdf_text(text))
        self.ln(1.5)


def item_colour(item):
    if item["match"] == "Probably someone else":
        return MUTED
    return "#B5654F" if HIGH_TYPES & set(item["exposed"]) else "#C6A15B"


def top_actions(items, n=5):
    mine = [i for i in items if i["match"] != "Probably someone else"]
    ranked = sorted(
        mine,
        key=lambda i: (
            not (HIGH_TYPES & set(i["exposed"])),
            EFFORTS.index(i["effort"]),
        ),
    )
    return ranked[:n]


def summary_pdf(result):
    items = result["items"]
    mine = [i for i in items if i["match"] != "Probably someone else"]
    pdf = Report()
    pdf.band(f"Summary for {result['name']}", f"Generated {result['finished']}")
    pdf.cards(
        [
            ("Exposure level", result["level"]),
            ("Pages about you", str(len(mine))),
            (
                "Sensitive details",
                str(sum(1 for i in mine if HIGH_TYPES & set(i["exposed"]))),
            ),
            ("Quick fixes", str(sum(1 for i in mine if i["effort"] == "Quick"))),
        ]
    )
    kinds = sorted({t for i in mine for t in i["exposed"]})
    pdf.section(
        "What's out there",
        (
            (
                "Pages that appear to be about you expose: "
                + ", ".join(kinds).lower()
                + "."
            )
            if kinds
            else "We didn't find pages exposing your personal information."
        ),
    )
    actions = top_actions(items)
    if actions:
        pdf.section("Your top actions")
        for a in actions:
            pdf.item(
                item_colour(a),
                f"{a['site']} ({a['page_type'].lower()}): "
                f"{', '.join(a['exposed']).lower()}",
                [("", a["removal"])],
            )
    if result.get("breaches"):
        pdf.section(
            "Data breaches",
            f"Your email appears in {len(result['breaches'])} known data breach(es). "
            "Change those passwords and turn on multi-factor authentication.",
        )
    pdf.section(
        "Next",
        "Your full report has step-by-step removal guidance for every page found. "
        "IDkat has "
        "now deleted your results.",
    )
    return bytes(pdf.output())


def full_pdf(result):
    items = result["items"]
    mine = [i for i in items if i["match"] != "Probably someone else"]
    others = [i for i in items if i["match"] == "Probably someone else"]
    pdf = Report()
    pdf.band(
        f"Full report and action plan: {result['name']}",
        f"Generated {result['finished']}",
    )
    pdf.section(
        "How to read this report",
        "Each entry shows where your information appears, what kind of "
        "information it is, and how to remove or hide it. IDkat never repeats the "
        "details themselves. "
        "Red markers show sensitive details (such as your address, phone number or "
        "date of birth); "
        "amber markers show other details. Start with red, quick fixes.",
    )
    pdf.section(f"Pages about you ({len(mine)})")
    for i in mine:
        link = f" Opt-out or settings: {i['removal_link']}" if i["removal_link"] else ""
        pdf.item(
            item_colour(i),
            f"{i['site']} · {i['page_type']} · {i['match']}",
            [
                ("", "Exposes: " + ", ".join(i["exposed"]).lower()),
                ("", f"What to do ({i['effort'].lower()}): {i['removal']}{link}"),
                ("I", f"Page: {i['url'] or 'no verified link'}"),
            ],
        )
    if others:
        pdf.section(
            "Possibly other people with your name",
            "These pages seem to be about someone else. Check "
            "them in case they're about you.",
        )
        for i in others:
            pdf.item(
                MUTED,
                f"{i['site']} · {i['page_type']}",
                [("I", f"Page: {i['url'] or 'no verified link'}")],
            )
    if result.get("breaches"):
        pdf.section("Data breaches involving your email")
        for b in result["breaches"]:
            pdf.item(
                "#B5654F", f"{b['name']} ({b['date']})", [("", f"Exposed: {b['data']}")]
            )
    elif result.get("breaches") == []:
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
# 5. PAGES
# ============================================================================
st.markdown(
    f"""<style>
.stApp {{ background:{INK}; color:{BONE}; }}
.idk-band {{ background:#1A1814; border:1px solid #2C2822; padding:22px 26px; margin-bottom:16px; }}
.idk-band .eyebrow {{ font-size:0.72rem; letter-spacing:0.22em; color:{MUTED}; text-transform:uppercase; }}
.idk-band .title {{ font-size:2.2rem; color:{BONE}; font-weight:600; line-height:1.1; }}
.idk-band .sub {{ color:{SAND}; font-style:italic; margin-top:4px; }}
</style>
<div class="idk-band"><div class="eyebrow">Your online footprint</div><div
class="title">🐾 IDkat</div>
<div class="sub">Find where your personal information appears online, and how to remove
it.</div></div>""",
    unsafe_allow_html=True,
)

purge_expired()
ready = (
    bool(app_secret())
    and smtp_ready()
    and bool(secret("GEMINI_API_KEY"))
    and bool(secret("APP_URL"))
)
if not ready:
    st.error(
        "IDkat isn't set up yet. The administrator needs to add IDKAT_SECRET (at least "
        "32 characters), "
        "APP_URL, GEMINI_API_KEY and the SMTP email settings to the app's Secrets."
    )
    st.stop()

# Arriving from an emailed link
if st.query_params.get("t") and not signed_in_email():
    email = read_token(st.query_params.get("t"), "link", single_use=True)
    del st.query_params["t"]
    if email:
        st.session_state.email = email
        st.query_params["s"] = make_token(email, SESSION_HOURS * 60, "session")
    else:
        st.error(
            "That sign-in link has expired or has already been used. Please request a "
            "new one."
        )

# Staying signed in after a refresh
if st.query_params.get("s") and not signed_in_email():
    email = read_token(st.query_params.get("s"), "session")
    if email:
        st.session_state.email = email
    else:
        del st.query_params["s"]

email = signed_in_email()

if st.session_state.pop("done_message", False):
    st.success(
        "Your reports are on their way to your inbox, and your results have been "
        "deleted from IDkat."
    )
if st.session_state.pop("deleted_message", False):
    st.success("Your results have been deleted from IDkat.")

if not email:
    st.markdown(
        "Enter your email and we'll send you a one-time sign-in link. No password "
        "needed."
    )
    with st.form("sign_in"):
        address = st.text_input("Your email address")
        with st.expander("Please read: what you're agreeing to", expanded=True):
            st.markdown(CONSENT_TEXT)
        agree_self = st.checkbox(
            "I'm using IDkat to check information about myself only"
        )
        agree_terms = st.checkbox("I agree to the terms above")
        send = st.form_submit_button("Email me a sign-in link", width="stretch")
    if send:
        address = address.strip().lower()
        if not EMAIL_RE.fullmatch(address):
            st.error("Please enter a valid email address.")
        elif not (agree_self and agree_terms):
            st.error("Please tick both boxes to continue.")
        elif not within_limit(
            "link_requests", fingerprint(address), MAX_LINKS_PER_HOUR, 3600
        ):
            st.error("Too many sign-in links requested. Please try again in an hour.")
        else:
            try:
                email_sign_in_link(address)
                st.success(
                    f"Check your inbox: we've sent a sign-in link to {address}. It "
                    "works once, for "
                    f"{LINK_MINUTES} minutes."
                )
            except Exception:
                st.error(
                    "We couldn't send the email just now. Please try again shortly."
                )
    st.caption(
        "IDkat keeps nothing after your reports are sent. Only a scrambled fingerprint "
        "of your email and "
        f"the name you search is kept, for up to {NAME_LOCK_DAYS} days, to prevent "
        "misuse."
    )
    st.stop()

top1, top2 = st.columns([3, 1])
top1.markdown(f"Signed in as **{html.escape(email)}**")
if top2.button("Sign out", width="stretch"):
    sign_out()
    st.rerun()

job = my_job(email)


@st.fragment(run_every=3)
def progress_panel():
    current = my_job(email)
    if current and current["status"] != "running":
        st.rerun(scope="app")
    if current:
        st.info(
            f"⏳ Searching: {current['progress']} "
            f"({int(time.time() - current['started'])}s)  \n"
            "You can close this page. We'll email you a link when your results are "
            "ready."
        )


if job and job["status"] == "running":
    progress_panel()
    st.stop()

if job and job["status"] == "failed":
    st.error(job["error"])
    delete_my_results(email)
    job = None

if job and job["status"] == "done":
    result = job["result"]
    items = result["items"]
    mine = [i for i in items if i["match"] != "Probably someone else"]
    left = RESULTS_HOURS * 60 - int((time.time() - job["started"]) / 60)
    st.subheader(f"Your results: {result['level']} exposure")
    c1, c2, c3 = st.columns(3)
    c1.metric("Pages about you", len(mine))
    c2.metric(
        "With sensitive details", sum(1 for i in mine if HIGH_TYPES & set(i["exposed"]))
    )
    c3.metric("Quick fixes", sum(1 for i in mine if i["effort"] == "Quick"))
    for i in items:
        icon = (
            "⚪"
            if i["match"] == "Probably someone else"
            else ("🔴" if HIGH_TYPES & set(i["exposed"]) else "🟠")
        )
        with st.expander(f"{icon} {i['site']} · {i['page_type']} · {i['match']}"):
            st.markdown(f"**Exposes:** {html.escape(', '.join(i['exposed']).lower())}")
            st.markdown(
                f"**What to do ({i['effort'].lower()}):** {html.escape(i['removal'])}"
            )
            if i["url"]:
                st.markdown(f"[Open the page]({i['url']})")
            if i["removal_link"]:
                st.markdown(f"[Opt-out or settings page]({i['removal_link']})")
    if result.get("breaches"):
        st.warning(
            f"Your email appears in {len(result['breaches'])} known data breach(es). "
            "Details are in your report."
        )
    st.divider()
    st.markdown(
        "Get your one-page summary and full action plan by email. **Your results are "
        "then deleted from "
        "IDkat.** If you do nothing, they're deleted automatically in about "
        f"{max(left, 1)} minutes."
    )
    b1, b2 = st.columns(2)
    if b1.button(
        "📧 Email my reports and delete my results", type="primary", width="stretch"
    ):
        try:
            with st.spinner("Preparing your reports"):
                attachments = [
                    ("IDkat_summary.pdf", summary_pdf(result)),
                    ("IDkat_full_report.pdf", full_pdf(result)),
                ]
                send_email(
                    email,
                    "Your IDkat reports",
                    "Attached are your IDkat reports: a one-page summary and a full "
                    "action plan with "
                    "removal steps for each page found.\n\nIDkat has now deleted your "
                    "results. To "
                    "check again later, just sign in with a new link.\n",
                    attachments,
                )
            delete_my_results(email)
            sign_out()
            st.session_state.done_message = True
            st.rerun()
        except Exception:
            st.error(
                "We couldn't send your reports just now. Please try again in a moment."
            )
    if b2.button("🗑️ Delete my results without emailing", width="stretch"):
        delete_my_results(email)
        sign_out()
        st.session_state.deleted_message = True
        st.rerun()
    st.stop()

st.subheader("Search for your information")
st.caption(
    "IDkat only searches for you. For your protection, the name you search is locked "
    "to your email "
    f"for {NAME_LOCK_DAYS} days."
)
with st.form("scan"):
    name = st.text_input("Your full name")
    aka = st.text_input(
        "Other names or usernames you use (optional)",
        placeholder="e.g. maiden name, nickname, @handle",
    )
    location = st.text_input(
        "Your city or region (optional, helps rule out other people)"
    )
    channels = st.multiselect("Where to look", list(CHANNELS), default=list(CHANNELS))
    include_email = st.checkbox(
        "Also look for pages and data breaches showing my email address", value=True
    )
    confirm = st.checkbox(
        "I confirm this is my own name, and I'm searching for information about myself"
    )
    go = st.form_submit_button("Start search", type="primary", width="stretch")
if go:
    clean_name = re.sub(r"\s+", " ", name).strip()
    owner = fingerprint(email)
    lock = STORE["names"].get(owner)
    if not clean_name or not channels:
        st.error("Please enter your name and choose at least one place to look.")
    elif not confirm:
        st.error("Please confirm you're searching for yourself.")
    elif lock and lock["name"] != fingerprint(clean_name):
        st.error(
            "This email is already linked to a different name. IDkat only lets you "
            "search for yourself."
        )
    elif not within_limit("scans", owner, MAX_SCANS_PER_DAY, 86400):
        st.error(
            f"You can run up to {MAX_SCANS_PER_DAY} searches a day. Please try again "
            "tomorrow."
        )
    elif not within_limit(
        "daily_total", "all", int(secret("DAILY_SCAN_CAP", 50)), 86400
    ):
        st.error("IDkat has reached today's limit. Please try again tomorrow.")
    else:
        with STORE["lock"]:
            STORE["names"][owner] = {
                "name": fingerprint(clean_name),
                "until": time.time() + NAME_LOCK_DAYS * 86400,
            }
        start_scan(
            email,
            {
                "name": clean_name,
                "aka": aka.strip(),
                "location": location.strip(),
                "email": email,
                "include_email": include_email,
            },
            channels,
        )
        st.rerun()
