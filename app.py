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
    "- your name, any other names and your city (if you give them) are used to search "
    "the "
    "public web, processed by Google's Gemini AI service. Your email address and "
    "occupation are "
    "only used in the search if you choose that. The details you give to confirm which "
    "pages "
    "are yours never leave IDkat;\n"
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
    if notify and smtp_ready() and secret("APP_URL"):
        try:
            send_email(
                profile["email"],
                "Your IDkat results are ready",
                "Your IDkat search has finished. Sign in to check your results and get "
                "your reports "
                f"(this link works once, for {LINK_MINUTES} "
                f"minutes):\n\n{sign_in_link(profile['email'])}\n\n"
                f"Your results will be deleted in {RESULTS_HOURS} hours if you don't "
                "get your reports "
                "before then.\n",
            )
        except Exception:
            pass


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
    div[data-baseweb="input"] input::placeholder, textarea::placeholder { color: #777777
    !important; opacity: 0.8 !important; }
    div[data-baseweb="select"] * { color: #14120F !important; font-weight: 600
    !important; }
    .stButton>button, .stFormSubmitButton>button { background-color: transparent
    !important; color: #F2EDE3 !important;
        border: 1px solid #C6BCA9 !important; border-radius: 2px !important; padding:
        0.65rem 1.4rem !important;
        font-size: 0.75rem !important; letter-spacing: 0.15em !important;
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
        font-size: 0.8rem; color: #8A8275; margin-top: 20px; }
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
    "color:#8A8275;"
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

# Staying signed in after a refresh: a signed token, so a server restart doesn't log you
# out
if st.query_params.get("s") and not signed_in_email():
    email = read_token(st.query_params.get("s"), "session")
    if email:
        st.session_state.email = email
    else:
        del st.query_params["s"]

email = signed_in_email()
clues = st.session_state.setdefault("clues", {})
not_me = st.session_state.setdefault("not_me", set())

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
        send = st.form_submit_button(
            "Email me a sign-in link", type="primary", width="stretch"
        )
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
    st.markdown(
        "<div class='disclaimer-box'>IDkat keeps nothing after your reports are sent. "
        "Only a scrambled "
        "fingerprint of your email and the name you search is kept, for up to "
        f"{NAME_LOCK_DAYS} days, to "
        "prevent misuse.</div>",
        unsafe_allow_html=True,
    )
    st.stop()

top1, top2 = st.columns([3, 1])
top1.markdown(f"Signed in as **{html.escape(email)}**")
if top2.button("Sign out", width="stretch"):
    sign_out()
    st.rerun()

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


job = my_job(email)


@st.fragment(run_every=3)
def progress_panel():
    current = my_job(email)
    if current and current["status"] != "running":
        st.rerun(scope="app")
    if current:
        *_, line = tally(current["items"])
        st.info(
            f"⏳ {current['progress']} ({int(time.time() - current['started'])}s)  \nSo "
            f"far: {line}  \n"
            "You can close this page: we'll email you a link when your results are "
            "ready."
        )


if job and job["status"] == "running":
    progress_panel()
    question_form(
        ALL_ASKS,
        "q_live",
        "#### While you wait: help us rule out other people with your name",
        "Update my answers",
    )
    st.stop()

if job and job["status"] == "failed":
    st.error(job["error"])
    delete_my_results(email)
    job = None

if job and job["status"] == "done":
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
            "it 'Not me' if it "
            "isn't you: it will be left out of your reports."
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
        "Get your one-page summary and full action plan by email. Only pages confirmed "
        "as yours are "
        "included. **Your results and answers are then deleted from IDkat.** If you do "
        "nothing, they're "
        f"deleted automatically in about {max(left, 1)} minutes."
    )
    b1, b2 = st.columns(2)
    if b1.button(
        "📧 Email my reports and delete my results", type="primary", width="stretch"
    ):
        report = {
            "verified": verified,
            "others": others,
            "unverified": unverified,
            "breaches": job.get("breaches"),
            "name": job["name"],
            "finished": job["finished"],
        }
        try:
            with st.spinner("Preparing your reports"):
                attachments = [
                    ("IDkat_summary.pdf", summary_pdf(report)),
                    ("IDkat_full_report.pdf", full_pdf(report)),
                ]
                send_email(
                    email,
                    "Your IDkat reports",
                    "Attached are your IDkat reports: a one-page summary and a full "
                    "action plan with "
                    "removal steps for each page confirmed as yours.\n\nIDkat has now "
                    "deleted your results "
                    "and answers. To check again later, just sign in with a new link.\n",
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
    st.markdown("**Used for the search**")
    name = st.text_input("Your full name")
    aka = st.text_input(
        "Other names you're known by (optional)",
        placeholder="e.g. maiden name, nickname",
    )
    location = st.text_input(
        "Your city or region (optional, helps rule out other people)"
    )
    channels = st.multiselect("Where to look", list(CHANNELS), default=list(CHANNELS))
    include_email = st.checkbox(
        "Also look for pages and data breaches showing my email address",
        value=False,
        help="This sends your email address to Google's search AI and, if set up, to "
        "the Have I Been Pwned "
        "breach service. Leave it off to keep your email address within IDkat.",
    )
    st.markdown(
        "**About you, to rule out other people with your name** (optional, and you can "
        "add these later)"
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
        "I confirm this is my own name, and I'm searching for information about myself"
    )
    go = st.form_submit_button("Start search", type="primary", width="stretch")
if go:
    save_answers(*start_fields)
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
        not_me.clear()
        occupation = ", ".join(clues.get("Occupation", [])) if focus_work else ""
        start_scan(
            email,
            {
                "name": clean_name,
                "aka": aka.strip(),
                "location": location.strip(),
                "email": email,
                "include_email": include_email,
                "occupation": occupation,
            },
            channels,
        )
        st.rerun()
