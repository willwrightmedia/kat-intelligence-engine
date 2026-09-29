"""
IDkat v2: find and fix your personal information online.

- Create a username and password to log in. No email required for sign-up.
- IDkat searches the public web for information about YOU.
- Identifiers are matched locally in code to protect user privacy.
- Results show WHERE information is exposed and HOW to remove it.
- Reports contain ONLY verified user pages.
- Downloading your reports permanently purges all account and result data.
"""

import datetime
import hashlib
import hmac
import html
import io
import json
import re
import secrets as pysecrets
import threading
import time
import uuid
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
RESULTS_HOURS = 2
MAX_SCANS_PER_DAY = 2
INK, BONE, SAND, MUTED = "#14120F", "#F2EDE3", "#C6BCA9", "#8A8275"

CHANNELS = {
    "Social media": "public profiles, posts, photos and comments on Facebook, Instagram, X, LinkedIn, TikTok, YouTube, Threads, Pinterest and similar",
    "Forums and communities": "Reddit, Whirlpool, Quora, Stack Exchange, community forums and comment sections",
    "Blogs and personal sites": "blogs, personal websites, Medium, Substack and WordPress, including mentions in other people's posts",
    "People-search sites and data brokers": "people-search sites, data brokers, directories and lookup sites that list names with addresses, phone numbers, relatives or ages",
    "Other public listings": "business and association registers, club, school and event pages, review sites, old CVs and other pages that mention the person",
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
MATCHES = ("Likely you", "Unconfirmed", "Someone else")
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

_SECRET_CACHE = {}
SECRET_NAMES = ("IDKAT_SECRET", "GEMINI_API_KEY", "GEMINI_MODEL", "HIBP_API_KEY", "DAILY_SCAN_CAP")


def secret(name, default=None):
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
# 1. MEMORY-ONLY STORE
# ============================================================================
@st.cache_resource
def _store():
    return {
        "lock": threading.Lock(),
        "users": {},      # username -> { salt, pw_hash }
        "scans": {},
        "jobs": {},
        "daily_total": {},
    }


STORE = _store()


def hash_password(password: str, salt: bytes = None) -> tuple[str, str]:
    """Hashes password with PBKDF2-HMAC-SHA256."""
    if salt is None:
        salt = pysecrets.token_bytes(16)
    pw_hash = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 100_000)
    return salt.hex(), pw_hash.hex()


def verify_password(password: str, salt_hex: str, pw_hash_hex: str) -> bool:
    salt = bytes.fromhex(salt_hex)
    _, new_hash = hash_password(password, salt)
    return hmac.compare_digest(new_hash, pw_hash_hex)


def fingerprint(value):
    return hmac.new(
        app_secret() or b"idkat", str(value).strip().lower().encode(), "sha256"
    ).hexdigest()[:24]


def purge_expired():
    now = time.time()
    with STORE["lock"]:
        for job_id in [
            j for j, job in STORE["jobs"].items() if now - job["started"] > RESULTS_HOURS * 3600
        ]:
            del STORE["jobs"][job_id]
        for bucket in ("scans",):
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
# 2. PRIVATE EVIDENCE MATCHING (LOCAL ENGINE)
# ============================================================================
class LocalEvidenceExtractor:
    @staticmethod
    def evaluate(item, clues):
        matching_clues = []
        conflicting_clues = []

        url = norm_url(item.get("url", ""))
        snippet = (item.get("site", "") + " " + item.get("snippet", "")).lower()

        for known_link in clues.get("known_links", []):
            if known_link and norm_url(known_link) in url:
                matching_clues.append("Known personal profile link")

        for handle in clues.get("usernames", []):
            clean_handle = handle.lower().lstrip("@").strip()
            if clean_handle and (clean_handle in snippet or clean_handle in url):
                matching_clues.append(f"Matching username (@{clean_handle})")

        for org in clues.get("workplaces_schools", []):
            if org.strip() and org.lower() in snippet:
                matching_clues.append(f"Matching workplace/school ({org})")

        user_locations = [clues.get("current_city", "")] + clues.get("past_cities", [])
        for loc in user_locations:
            if loc.strip() and loc.lower() in snippet:
                matching_clues.append(f"Matching location ({loc})")

        detected_cities = item.get("detected_cities", [])
        for city in detected_cities:
            if city.lower() not in [l.lower() for l in user_locations if l.strip()]:
                conflicting_clues.append(f"Different location detected ({city})")

        if len(conflicting_clues) > 0:
            match_status = "Someone else"
        elif len(matching_clues) >= 2 or any("Known personal profile link" in m for m in matching_clues):
            match_status = "Likely you"
        else:
            match_status = "Unconfirmed"

        item["matching_clues"] = matching_clues
        item["conflicting_clues"] = conflicting_clues
        item["match"] = match_status
        return item


# ============================================================================
# 3. SEARCH ENGINE (Google Search via Gemini)
# ============================================================================
class Exposure(BaseModel):
    site: str = Field(description="The website's name.")
    page_type: str = Field(default="Other", description="One of: " + ", ".join(PAGE_TYPES) + ".")
    exposed: list[str] = Field(
        default=[],
        description="Types of personal info exposed, from: " + ", ".join(EXPOSED_TYPES) + ". Types only.",
    )
    detected_cities: list[str] = Field(
        default=[], description="Any city or location names specifically associated with this person on the page."
    )
    snippet: str = Field(default="", description="A short non-sensitive summary of text found.")
    removal: str = Field(description="How to remove/hide in 1-2 practical sentences.")
    removal_link: str = Field(default="None", description="Exact opt-out/settings link if verified.")
    effort: str = Field(default="Moderate", description="Quick, Moderate or Hard.")
    source_url: str = Field(default="None", description="Exact page URL from verified sources.")


class ExposureExtraction(BaseModel):
    exposures: list[Exposure] = []


EMAIL_RE = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+")
PHONE_RE = re.compile(r"(?:\+?\d[\d\s().-]{7,}\d)")
STREET_RE = re.compile(
    r"\b\d{1,5}\s+[A-Z][a-z]+(?:\s+[A-Z][a-z]+)*\s+(?:St|Street|Rd|Road|Ave|Avenue|Dr|Drive|Ct|Court|Pl|Place|Cres|Crescent|Pde|Parade|Hwy|Highway|Lane|Ln|Tce|Terrace|Way|Blvd)\b"
)


def scrub(text):
    text = EMAIL_RE.sub("[email hidden]", str(text or ""))
    text = STREET_RE.sub("[address hidden]", text)

    def hide(match):
        value = match.group()
        if re.fullmatch(r"\s*(19|20)\d{2}\s*[-–]\s*(19|20)\d{2}\s*", value):
            return value
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
            r = requests.get(uri, allow_redirects=True, timeout=8, headers=headers, stream=True)
            r.close()
            status, final = r.status_code, r.url
    except requests.RequestException as exc:
        resp = getattr(exc, "response", None)
        if resp is not None:
            status, final = resp.status_code, resp.url
    if status is not None and status < 400:
        return final
    return ""


def pick(value, options, default):
    text = str(value or "").strip().lower()
    return next(
        (o for o in options if o.lower() == text or o.lower().split(" ")[0] == text.split(" ")[0]),
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
        return client.models.generate_content(model=model, contents=prompt, config=config)
    except Exception as exc:
        if "not found" in str(exc).lower() and model != FALLBACK_MODEL:
            return client.models.generate_content(model=FALLBACK_MODEL, contents=prompt, config=config)
        raise


def search_prompt(profile, focus):
    aka = f" Alternate names: {profile['aka']}." if profile["aka"] else ""
    where = f" City: {profile['location']}." if profile["location"] else ""
    return f"""Today is {datetime.date.today():%d %B %Y}.
Find public web pages referencing: "{profile['name']}".{aka}{where}
Focus on: {focus}.
Report site, exact URL, exposed types, and any location names mentioned. Never disclose sensitive private details in output text."""


def extraction_prompt(profile, notes, sources):
    listing = "\n".join(f"- {url}  ({title})" for title, url in sources) or "(none)"
    return f"""Convert search notes into JSON for target person "{profile['name']}".

VERIFIED SOURCES
{listing}

NOTES
{notes[:25000]}"""


def hibp_breaches(email):
    key = secret("HIBP_API_KEY")
    if not key or not email:
        return None
    try:
        r = requests.get(
            f"https://haveibeenpwned.com/api/v3/breachedaccount/{requests.utils.quote(email)}",
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


def run_scan(job, profile, clues, channels, api_key, model):
    try:
        client = model_client(api_key)
        groups = [channels[: (len(channels) + 1) // 2], channels[(len(channels) + 1) // 2 :]]
        items, seen = [], set()

        for n, group in enumerate([g for g in groups if g], 1):
            job["progress"] = f"Searching pass {n}: {', '.join(group).lower()}"
            resp = generate(client, model, search_prompt(profile, "; ".join(CHANNELS[c] for c in group)), search=True)

            sources = []
            for cand in getattr(resp, "candidates", None) or []:
                meta = getattr(cand, "grounding_metadata", None)
                for chunk in (getattr(meta, "grounding_chunks", None) or []) if meta else []:
                    web = getattr(chunk, "web", None)
                    if web and getattr(web, "uri", None):
                        final = resolve_redirect(web.uri)
                        if final:
                            sources.append((getattr(web, "title", "") or "", final))

            allowed = {norm_url(u) for _, u in sources}
            notes = resp.text or ""
            if not notes.strip():
                continue

            job["progress"] = f"Evaluating evidence pass ({n})"
            data = generate(client, model, extraction_prompt(profile, notes, sources), schema=ExposureExtraction)
            parsed = getattr(data, "parsed", None)
            raw = (
                parsed.model_dump()
                if isinstance(parsed, BaseModel)
                else json.loads(re.sub(r"^```(?:json)?\s*|\s*```$", "", (data.text or "").strip()) or "{}")
            )

            for e in raw.get("exposures", []):
                item = {
                    "site": scrub(e.get("site"))[:80] or "Unknown site",
                    "page_type": pick(e.get("page_type"), PAGE_TYPES, "Other"),
                    "exposed": [pick(x, EXPOSED_TYPES, "Other") for x in e.get("exposed", []) if x][:8] or ["Other"],
                    "snippet": scrub(e.get("snippet", ""))[:300],
                    "detected_cities": e.get("detected_cities", []),
                    "removal": scrub(e.get("removal"))[:400],
                    "effort": pick(e.get("effort"), EFFORTS, "Moderate"),
                    "url": (e.get("source_url") if norm_url(e.get("source_url")) in allowed else ""),
                    "removal_link": (e.get("removal_link") if norm_url(e.get("removal_link")) in allowed else ""),
                }
                item = LocalEvidenceExtractor.evaluate(item, clues)

                key = norm_url(item["url"]) or f"{item['site'].lower()}|{item['page_type']}"
                if key not in seen:
                    seen.add(key)
                    items.append(item)

        breaches = hibp_breaches(profile.get("check_email")) if profile.get("check_email") else None

        job["result"] = {
            "items": items,
            "breaches": breaches,
            "name": profile["name"],
            "finished": datetime.datetime.now().strftime("%d %b %Y %H:%M"),
        }
        job["status"] = "done"
    except Exception as exc:
        job["status"], job["error"] = "failed", f"Search halted: {str(exc)[:300]}"


def start_scan(username, profile, clues, channels):
    job = {
        "id": uuid.uuid4().hex[:12],
        "owner": fingerprint(username),
        "status": "running",
        "progress": "Starting search",
        "started": time.time(),
        "result": None,
        "error": "",
    }
    with STORE["lock"]:
        STORE["jobs"][job["id"]] = job
    api_key = str(secret("GEMINI_API_KEY", "") or "")
    model = str(secret("GEMINI_MODEL", DEFAULT_MODEL))
    threading.Thread(
        target=run_scan, args=(job, profile, clues, channels, api_key, model), daemon=True
    ).start()


def my_job(username):
    owner = fingerprint(username)
    jobs = [j for j in list(STORE["jobs"].values()) if j["owner"] == owner]
    return max(jobs, key=lambda j: j["started"]) if jobs else None


def delete_user_and_results(username):
    """Purges all active scan jobs and account details for the user from memory."""
    owner = fingerprint(username)
    with STORE["lock"]:
        for job_id in [j for j, job in STORE["jobs"].items() if job["owner"] == owner]:
            del STORE["jobs"][job_id]
        if username.lower() in STORE["users"]:
            del STORE["users"][username.lower()]


# ============================================================================
# 4. REPORT PDF GENERATION
# ============================================================================
def _pdf_fonts():
    base = Path(matplotlib.get_data_path()) / "fonts" / "ttf"
    files = {"": "DejaVuSans.ttf", "B": "DejaVuSans-Bold.ttf", "I": "DejaVuSans-Oblique.ttf"}
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
        self.cell(0, 5, pdf_text(f"IDkat · confidential to you · page {self.page_no()}"), align="C")

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


def generate_full_pdf(verified_items, breaches, excluded_count, name, finished):
    pdf = Report()
    pdf.band(f"Full Action Plan: {name}", f"Generated {finished}")
    pdf.section("Your Verified Footprint", f"Showing {len(verified_items)} confirmed page(s).")

    for item in verified_items:
        link = f" Opt-out link: {item['removal_link']}" if item['removal_link'] else ""
        pdf.item(
            "#B5654F",
            f"{item['site']} · {item['page_type']}",
            [
                ("", f"Exposes: {', '.join(item['exposed'])}"),
                ("", f"Action ({item['effort']}): {item['removal']}{link}"),
                ("I", f"URL: {item['url'] or 'unlinked'}"),
            ],
        )

    if breaches:
        pdf.section("Data Breaches", f"Your email was found in {len(breaches)} breach(es).")
        for b in breaches:
            pdf.item("#B5654F", f"{b['name']} ({b['date']})", [("", f"Data: {b['data']}")])

    if excluded_count > 0:
        pdf.section("Privacy Notice", f"{excluded_count} page(s) identified as belonging to other individuals were omitted.")

    return bytes(pdf.output())


# ============================================================================
# 5. USER INTERFACE & AUTHENTICATION
# ============================================================================
st.markdown(
    f"""<style>
.stApp {{ background:{INK}; color:{BONE}; }}
.idk-band {{ background:#1A1814; border:1px solid #2C2822; padding:22px 26px; margin-bottom:16px; }}
.idk-band .eyebrow {{ font-size:0.72rem; letter-spacing:0.22em; color:{MUTED}; text-transform:uppercase; }}
.idk-band .title {{ font-size:2.2rem; color:{BONE}; font-weight:600; line-height:1.1; }}
.idk-band .sub {{ color:{SAND}; font-style:italic; margin-top:4px; }}
</style>
<div class="idk-band"><div class="eyebrow">Your online footprint</div><div class="title">🐾 IDkat v2</div>
<div class="sub">Find where your personal information appears online, with strict local evidence-based matching.</div></div>""",
    unsafe_allow_html=True,
)

purge_expired()

if "username" not in st.session_state:
    st.session_state.username = None

# Login / Sign-up View
if not st.session_state.username:
    tab1, tab2 = st.tabs(["Sign In", "Create Account"])

    with tab1:
        st.subheader("Log in to IDkat")
        with st.form("login_form"):
            user_in = st.text_input("Username")
            pass_in = st.text_input("Password", type="password")
            login_btn = st.form_submit_button("Sign In", type="primary")

        if login_btn:
            u = user_in.strip().lower()
            with STORE["lock"]:
                user_data = STORE["users"].get(u)
            if user_data and verify_password(pass_in, user_data["salt"], user_data["pw_hash"]):
                st.session_state.username = user_in.strip()
                st.rerun()
            else:
                st.error("Invalid username or password.")

    with tab2:
        st.subheader("Create a temporary account")
        st.caption("Account records live in RAM only and are deleted immediately upon downloading your report.")
        with st.form("signup_form"):
            new_user = st.text_input("Choose a Username")
            new_pass = st.text_input("Choose a Password", type="password")
            confirm_pass = st.text_input("Confirm Password", type="password")
            signup_btn = st.form_submit_button("Create Account", type="primary")

        if signup_btn:
            u_clean = new_user.strip().lower()
            if not u_clean or not new_pass:
                st.error("Please fill in all fields.")
            elif new_pass != confirm_pass:
                st.error("Passwords do not match.")
            elif len(new_pass) < 6:
                st.error("Password must be at least 6 characters long.")
            else:
                with STORE["lock"]:
                    if u_clean in STORE["users"]:
                        st.error("Username already taken. Please choose another.")
                    else:
                        s_hex, h_hex = hash_password(new_pass)
                        STORE["users"][u_clean] = {"salt": s_hex, "pw_hash": h_hex}
                        st.session_state.username = new_user.strip()
                        st.success("Account created!")
                        st.rerun()
    st.stop()

# Signed-in user view
top1, top2 = st.columns([3, 1])
top1.markdown(f"Signed in as **{html.escape(st.session_state.username)}**")
if top2.button("Log out"):
    st.session_state.username = None
    st.rerun()

job = my_job(st.session_state.username)

if job and job["status"] == "running":
    st.info(f"⏳ {job['progress']}... Searching web indexes.")
    time.sleep(2)
    st.rerun()

if job and job["status"] == "done":
    res = job["result"]
    raw_items = res["items"]

    if "user_confirmations" not in st.session_state:
        st.session_state.user_confirmations = {}

    st.subheader("Review Search Results")
    st.caption("Confirm unverified pages below before generating your downloadable report.")

    verified = []
    excluded_count = 0

    for idx, item in enumerate(raw_items):
        item_id = f"item_{idx}"
        match_status = item["match"]

        user_choice = st.session_state.user_confirmations.get(item_id, None)

        if user_choice == "yes" or match_status == "Likely you":
            verified.append(item)
            st.markdown(f"✅ **{item['site']}** ({item['page_type']}) — *Likely You / Confirmed*")
            st.caption(f"Evidence: {', '.join(item['matching_clues']) if item['matching_clues'] else 'Confirmed by you'}")
        elif match_status == "Someone else" or user_choice == "no":
            excluded_count += 1
        else:
            st.warning(f"❓ **Unconfirmed Page:** {item['site']} ({item['page_type']})")
            if item.get("snippet"):
                st.caption(f"Context snippet: *\"{item['snippet']}\"*")
            col_a, col_b = st.columns(2)
            if col_a.button("This is me", key=f"yes_{idx}"):
                st.session_state.user_confirmations[item_id] = "yes"
                st.rerun()
            if col_b.button("Not me", key=f"no_{idx}"):
                st.session_state.user_confirmations[item_id] = "no"
                st.rerun()

    st.divider()
    st.markdown(f"### 📊 Report Summary")
    st.markdown(f"- **Pages to be included in report:** {len(verified)}")
    st.markdown(f"- **Pages omitted (belong to other people):** {excluded_count}")

    st.divider()

    # Direct File Download + Auto-Wipe
    pdf_bytes = generate_full_pdf(verified, res["breaches"], excluded_count, res["name"], res["finished"])

    if st.download_button(
        label="📥 Download verified report & wipe my data",
        data=pdf_bytes,
        file_name=f"IDkat_Report_{res['name'].replace(' ', '_')}.pdf",
        mime="application/pdf",
        type="primary",
    ):
        delete_user_and_results(st.session_state.username)
        st.session_state.username = None
        st.success("Report downloaded! Account and search data purged from memory.")
        st.rerun()
    st.stop()

# Search Form
st.subheader("Search your online footprint")
with st.form("scan_form"):
    name = st.text_input("Your full name")
    aka = st.text_input("Other names used (maiden name, nicknames)", placeholder="Optional")
    location = st.text_input("Current city/region (sent to search to disambiguate)", placeholder="e.g. Geelong")

    st.markdown("---")
    st.markdown("#### Private Identifying Clues (Never sent to search, evaluated locally)")
    st.caption("These details are kept strictly in local code to evaluate matching confidence.")

    known_links = st.text_area("Links you know are yours (one per line)", placeholder="https://linkedin.com/in/yourname\nhttps://yourwebsite.com")
    past_cities = st.text_input("Past cities or suburbs lived in (comma-separated)", placeholder="e.g. Melbourne, Ballarat")
    workplaces = st.text_input("Current & past workplaces or schools (comma-separated)", placeholder="e.g. Acme Corp, Monash Uni")
    usernames = st.text_input("Usernames & handles (comma-separated)", placeholder="e.g. @janedoe88")
    check_email = st.text_input("Email address (Optional: used only for Have I Been Pwned breach checks)", placeholder="user@example.com")

    st.markdown("---")
    channels = st.multiselect("Channels to search", list(CHANNELS), default=list(CHANNELS))
    confirm = st.checkbox("I confirm I am searching for myself")

    submit = st.form_submit_button("Start Private Search", type="primary")

if submit:
    clean_name = re.sub(r"\s+", " ", name).strip()
    if not clean_name or not confirm:
        st.error("Please provide your name and confirm you are searching for yourself.")
    else:
        clues_data = {
            "known_links": [l.strip() for l in known_links.split("\n") if l.strip()],
            "current_city": location.strip(),
            "past_cities": [c.strip() for c in past_cities.split(",") if c.strip()],
            "workplaces_schools": [w.strip() for w in workplaces.split(",") if w.strip()],
            "usernames": [u.strip() for u in usernames.split(",") if u.strip()],
        }

        total_clues = sum(len(v) if isinstance(v, list) else (1 if v else 0) for v in clues_data.values())
        if total_clues < 2:
            st.warning("⚠️ Common Name Prompt: Adding more clues helps rule out namesakes much faster.")

        start_scan(
            st.session_state.username,
            {
                "name": clean_name,
                "aka": aka.strip(),
                "location": location.strip(),
                "check_email": check_email.strip(),
            },
            clues_data,
            channels,
        )
        st.rerun()
