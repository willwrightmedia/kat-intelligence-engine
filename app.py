"""
IDkat v2.5: Deep Multi-Pass Online Footprint & Work History Search

- Supports 1 to 50 configurable search passes.
- Expanded focus on professional history, directorships, and employment details.
- Deduplicates results in real-time across passes.
- Downloads reports in PDF, Word (.docx), and Plain Text (.txt).
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

import docx
import matplotlib
import requests
import streamlit as st
from fpdf import FPDF
from google import genai
from google.genai import types
from pydantic import BaseModel, Field

st.set_page_config(page_title="IDkat Deep Search", page_icon="🐾", layout="centered")

# ============================================================================
# 0. SETTINGS & CONSTANTS
# ============================================================================
DEFAULT_MODEL = "gemini-3.8-flash"
FALLBACK_MODEL = "gemini-flash-latest"
RESULTS_HOURS = 4
INK, BONE, SAND, MUTED = "#14120F", "#F2EDE3", "#C6BCA9", "#8A8275"

SEARCH_STRATEGIES = [
    ("Social Profiles & Handles", "social media profiles, Instagram, LinkedIn, X/Twitter, Threads, YouTube, personal handles"),
    ("Current & Past Employment", "workplaces, job titles, company bio pages, team listings, staff directories, resume publications"),
    ("Company Directorships & Registers", "business registrations, company directorships, ASIC/corporate filings, domain registration WHOIS, ABN lookups"),
    ("Industry News & Articles", "press releases, news articles, media mentions, industry interviews, blog posts, guest articles"),
    ("Speaking & Events", "conference speaker bios, event panelist listings, academic papers, podcast appearances, webinars"),
    ("Forums & Communities", "forum posts, Reddit, Stack Overflow, Medium, Substack, comment sections, community contributions"),
    ("People Search & Data Brokers", "directories, whitepages, public record aggregates, people-finder databases"),
    ("Direct Handle & URL Checks", "exact match web searches for known usernames and domain references")
]

EXPOSED_TYPES = [
    "Workplace or Job Title",
    "Company Directorship / Business Ownership",
    "Home address",
    "Phone number",
    "Email address",
    "Date of birth or age",
    "Photos / Media",
    "Usernames / Social Handles",
    "Location or City",
    "Financial / ID details",
    "Posts, Opinions or Articles",
    "Other",
]

PAGE_TYPES = [
    "Social profile",
    "Workplace / Corporate Bio",
    "Company Register / Business Directory",
    "News / Article",
    "Forum post",
    "Blog post",
    "Other",
]

_SECRET_CACHE = {}
SECRET_NAMES = ("IDKAT_SECRET", "GEMINI_API_KEY", "GEMINI_MODEL", "HIBP_API_KEY")

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
        "users": {},
        "jobs": {},
    }

STORE = _store()

def hash_password(password: str, salt: bytes = None) -> tuple[str, str]:
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

# ============================================================================
# 2. HELPER FUNCTIONS
# ============================================================================
def is_url(value):
    v = str(value or "").strip()
    return v.startswith("http") and v.lower() not in ("none", "null")

def norm_url(url):
    if not is_url(url):
        return ""
    p = urlparse(url.strip())
    return f"{p.netloc.lower().removeprefix('www.')}{p.path.rstrip('/')}"

def model_client(api_key):
    key = re.sub(r"[^\w.\-]", "", str(api_key or "").strip())
    return genai.Client(api_key=key, vertexai=False, enterprise=False)

# ============================================================================
# 3. LOCAL EVIDENCE MATCHING
# ============================================================================
class LocalEvidenceExtractor:
    @staticmethod
    def evaluate(item, clues):
        matching_clues = []
        conflicting_clues = []

        url = norm_url(item.get("url", ""))
        snippet = (item.get("site", "") + " " + item.get("snippet", "") + " " + item.get("work_details", "")).lower()

        # Check known URLs
        for known_link in clues.get("known_links", []):
            if known_link and norm_url(known_link) in url:
                matching_clues.append("Known personal profile link")

        # Check handles
        for handle in clues.get("usernames", []):
            clean_handle = handle.lower().lstrip("@").strip()
            if clean_handle and (clean_handle in snippet or clean_handle in url):
                matching_clues.append(f"Matching handle (@{clean_handle})")

        # Check workplaces & schools
        for org in clues.get("workplaces_schools", []):
            if org.strip() and org.lower() in snippet:
                matching_clues.append(f"Matching workplace/company ({org})")

        # Check cities
        user_locations = [clues.get("current_city", "")] + clues.get("past_cities", [])
        for loc in user_locations:
            if loc.strip() and loc.lower() in snippet:
                matching_clues.append(f"Matching location ({loc})")

        if len(matching_clues) >= 2 or any("Known personal profile link" in m for m in matching_clues):
            match_status = "Likely you"
        else:
            match_status = "Unconfirmed"

        item["matching_clues"] = matching_clues
        item["conflicting_clues"] = conflicting_clues
        item["match"] = match_status
        return item

# ============================================================================
# 4. DEEP MULTI-PASS SEARCH ENGINE
# ============================================================================
class Exposure(BaseModel):
    site: str = Field(description="The website's name.")
    page_type: str = Field(default="Other", description="Page classification.")
    exposed: list[str] = Field(default=[], description="Types of information found.")
    work_details: str = Field(default="", description="Any job titles, employer names, or professional roles mentioned on this page.")
    snippet: str = Field(default="", description="A short summary of what was found.")
    removal: str = Field(description="How to remove/hide in 1-2 practical sentences.")
    removal_link: str = Field(default="None", description="Exact opt-out/settings link if verified.")
    source_url: str = Field(default="None", description="Exact page URL.")

class ExposureExtraction(BaseModel):
    exposures: list[Exposure] = []

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
        if model != FALLBACK_MODEL:
            return client.models.generate_content(model=FALLBACK_MODEL, contents=prompt, config=config)
        raise

def run_deep_scan(job, profile, clues, max_passes, api_key, model):
    try:
        client = model_client(api_key)
        items, seen_urls = [], set()

        # Build query elements
        base_name = profile['name']
        handles = " ".join([f'"{u.strip()}"' for u in clues.get("usernames", []) if u.strip()])
        known_links = " ".join([f'"{l.strip()}"' for l in clues.get("known_links", []) if l.strip()])
        workplaces = " ".join([f'"{w.strip()}"' for w in clues.get("workplaces_schools", []) if w.strip()])
        location = profile.get('location', '')

        for pass_num in range(1, max_passes + 1):
            strategy_name, strategy_focus = SEARCH_STRATEGIES[(pass_num - 1) % len(SEARCH_STRATEGIES)]
            job["progress"] = f"Pass {pass_num}/{max_passes}: Searching {strategy_name}..."

            prompt = f"""Today is {datetime.date.today():%d %B %Y}.
Find public web pages referencing person: "{base_name}".
Additional clues to search:
Location: {location}
Workplaces/Companies: {workplaces}
Usernames/Handles: {handles}
Direct Links: {known_links}

Focus strategy for this pass: {strategy_focus}.
Find exact URLs, site names, job titles/professional roles exposed, and summaries."""

            resp = generate(client, model, prompt, search=True)

            sources = []
            for cand in getattr(resp, "candidates", None) or []:
                meta = getattr(cand, "grounding_metadata", None)
                for chunk in (getattr(meta, "grounding_chunks", None) or []) if meta else []:
                    web = getattr(chunk, "web", None)
                    if web and getattr(web, "uri", None):
                        sources.append((getattr(web, "title", "") or "", web.uri))

            allowed = {norm_url(u) for _, u in sources}
            notes = resp.text or ""
            if not notes.strip():
                continue

            # Extract structured items
            extract_prompt = f"""Convert search notes into JSON for target "{base_name}".

VERIFIED SOURCES
{chr(10).join([f"- {u} ({t})" for t, u in sources])}

NOTES
{notes[:25000]}"""

            data = generate(client, model, extract_prompt, schema=ExposureExtraction)
            parsed = getattr(data, "parsed", None)
            raw = (
                parsed.model_dump()
                if isinstance(parsed, BaseModel)
                else json.loads(re.sub(r"^```(?:json)?\s*|\s*```$", "", (data.text or "").strip()) or "{}")
            )

            for e in raw.get("exposures", []):
                url = e.get("source_url", "")
                norm = norm_url(url)
                if norm and norm in allowed and norm not in seen_urls:
                    seen_urls.add(norm)
                    item = {
                        "site": e.get("site", "Unknown site")[:80],
                        "page_type": e.get("page_type", "Other"),
                        "exposed": e.get("exposed", ["Other"]),
                        "work_details": e.get("work_details", ""),
                        "snippet": e.get("snippet", "")[:300],
                        "removal": e.get("removal", "Contact site administrator or check account privacy settings.")[:400],
                        "url": url,
                        "removal_link": e.get("removal_link", ""),
                    }
                    item = LocalEvidenceExtractor.evaluate(item, clues)
                    items.append(item)

        job["result"] = {
            "items": items,
            "name": profile["name"],
            "finished": datetime.datetime.now().strftime("%d %b %Y %H:%M"),
        }
        job["status"] = "done"
    except Exception as exc:
        job["status"], job["error"] = "failed", f"Search halted: {str(exc)[:300]}"

def start_deep_scan(username, profile, clues, max_passes):
    job = {
        "id": uuid.uuid4().hex[:12],
        "owner": fingerprint(username),
        "status": "running",
        "progress": "Initializing deep multi-pass scan...",
        "started": time.time(),
        "result": None,
        "error": "",
    }
    with STORE["lock"]:
        STORE["jobs"][job["id"]] = job
    api_key = str(secret("GEMINI_API_KEY", "") or "")
    model = str(secret("GEMINI_MODEL", DEFAULT_MODEL))
    threading.Thread(
        target=run_deep_scan, args=(job, profile, clues, max_passes, api_key, model), daemon=True
    ).start()

def my_job(username):
    owner = fingerprint(username)
    jobs = [j for j in list(STORE["jobs"].values()) if j["owner"] == owner]
    return max(jobs, key=lambda j: j["started"]) if jobs else None

def delete_user_data(username):
    owner = fingerprint(username)
    with STORE["lock"]:
        for job_id in [j for j, job in STORE["jobs"].items() if job["owner"] == owner]:
            del STORE["jobs"][job_id]
        if username.lower() in STORE["users"]:
            del STORE["users"][username.lower()]

# ============================================================================
# 5. MULTI-FORMAT REPORT EXPORTERS (PDF, DOCX, TXT)
# ============================================================================
def generate_pdf(verified_items, name, finished):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Helvetica", "B", 16)
    pdf.cell(0, 10, f"IDkat Footprint Report: {name}", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "I", 10)
    pdf.cell(0, 5, f"Generated on {finished}", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(5)

    for item in verified_items:
        pdf.set_font("Helvetica", "B", 11)
        pdf.cell(0, 6, f"{item['site']} ({item['page_type']})", new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("Helvetica", "", 9)
        pdf.multi_cell(0, 4, f"URL: {item['url']}\nExposes: {', '.join(item['exposed'])}\nWork History Details: {item.get('work_details', 'N/A')}\nSummary: {item['snippet']}\nRemoval Action: {item['removal']}\n")
        pdf.ln(3)
    return bytes(pdf.output())

def generate_docx(verified_items, name, finished):
    doc = docx.Document()
    doc.add_heading(f"IDkat Online Footprint Report: {name}", 0)
    doc.add_paragraph(f"Generated on {finished}")

    for item in verified_items:
        doc.add_heading(f"{item['site']} ({item['page_type']})", level=2)
        doc.add_paragraph(f"URL: {item['url']}")
        doc.add_paragraph(f"Information Exposed: {', '.join(item['exposed'])}")
        if item.get("work_details"):
            doc.add_paragraph(f"Work/Professional History: {item['work_details']}")
        doc.add_paragraph(f"Context Summary: {item['snippet']}")
        doc.add_paragraph(f"How to Remove: {item['removal']}")

    bio = io.BytesIO()
    doc.save(bio)
    return bio.getvalue()

def generate_txt(verified_items, name, finished):
    lines = [f"IDKAT ONLINE FOOTPRINT REPORT: {name}", f"Generated on {finished}", "="*50, ""]
    for item in verified_items:
        lines.append(f"Site: {item['site']} ({item['page_type']})")
        lines.append(f"URL: {item['url']}")
        lines.append(f"Exposed: {', '.join(item['exposed'])}")
        if item.get("work_details"):
            lines.append(f"Work Details: {item['work_details']}")
        lines.append(f"Summary: {item['snippet']}")
        lines.append(f"Removal: {item['removal']}")
        lines.append("-" * 40)
    return "\n".join(lines).encode("utf-8")

# ============================================================================
# 6. STREAMLIT INTERFACE
# ============================================================================
st.markdown(
    f"""<style>
.stApp {{ background:{INK}; color:{BONE}; }}
.idk-band {{ background:#1A1814; border:1px solid #2C2822; padding:22px 26px; margin-bottom:16px; }}
.idk-band .eyebrow {{ font-size:0.72rem; letter-spacing:0.22em; color:{MUTED}; text-transform:uppercase; }}
.idk-band .title {{ font-size:2.2rem; color:{BONE}; font-weight:600; line-height:1.1; }}
.idk-band .sub {{ color:{SAND}; font-style:italic; margin-top:4px; }}
</style>
<div class="idk-band"><div class="eyebrow">Deep Online Footprint Search</div><div class="title">🐾 IDkat v2.5</div>
<div class="sub">Multi-pass deep web search & professional history scanner.</div></div>""",
    unsafe_allow_html=True,
)

if "username" not in st.session_state:
    st.session_state.username = None

if not st.session_state.username:
    tab1, tab2 = st.tabs(["Sign In", "Create Account"])
    with tab1:
        with st.form("login"):
            u_in = st.text_input("Username")
            p_in = st.text_input("Password", type="password")
            if st.form_submit_button("Sign In", type="primary"):
                u_clean = u_in.strip().lower()
                with STORE["lock"]:
                    u_data = STORE["users"].get(u_clean)
                if u_data and verify_password(p_in, u_data["salt"], u_data["pw_hash"]):
                    st.session_state.username = u_in.strip()
                    st.rerun()
                else:
                    st.error("Invalid credentials.")
    with tab2:
        with st.form("signup"):
            nu = st.text_input("Choose Username")
            np = st.text_input("Choose Password", type="password")
            if st.form_submit_button("Create Account", type="primary"):
                if nu and np:
                    with STORE["lock"]:
                        if nu.strip().lower() in STORE["users"]:
                            st.error("Username taken.")
                        else:
                            s, h = hash_password(np)
                            STORE["users"][nu.strip().lower()] = {"salt": s, "pw_hash": h}
                            st.session_state.username = nu.strip()
                            st.rerun()
    st.stop()

top1, top2 = st.columns([3, 1])
top1.markdown(f"Signed in as **{html.escape(st.session_state.username)}**")
if top2.button("Log out"):
    st.session_state.username = None
    st.rerun()

job = my_job(st.session_state.username)

if job and job["status"] == "running":
    st.info(f"⏳ {job['progress']}")
    time.sleep(2)
    st.rerun()

if job and job["status"] == "done":
    res = job["result"]
    raw_items = res["items"]

    if "user_confirmations" not in st.session_state:
        st.session_state.user_confirmations = {}

    st.subheader(f"Review Search Results ({len(raw_items)} items found)")
    st.caption("Review candidate pages found during the deep scan. Click 'This is me' to include a page in your final report.")

    verified = []
    excluded = 0

    for idx, item in enumerate(raw_items):
        item_id = f"item_{idx}"
        choice = st.session_state.user_confirmations.get(item_id)

        if choice == "yes" or item["match"] == "Likely you":
            verified.append(item)
            with st.expander(f"✅ {item['site']} ({item['page_type']}) — Confirmed", expanded=False):
                st.write(f"**URL:** [{item['url']}]({item['url']})")
                st.write(f"**Exposed:** {', '.join(item['exposed'])}")
                if item.get("work_details"):
                    st.write(f"**Work Details:** {item['work_details']}")
                st.write(f"**Snippet:** {item['snippet']}")
        elif choice == "no":
            excluded += 1
        else:
            with st.container():
                st.warning(f"❓ **Candidate Page:** {item['site']} ({item['page_type']})")
                st.write(f"**URL:** [{item['url']}]({item['url']})")
                st.write(f"**Snippet:** *\"{item['snippet']}\"*")
                if item.get("work_details"):
                    st.write(f"**Work/Role Mentioned:** {item['work_details']}")
                col1, col2 = st.columns(2)
                if col1.button("This is me", key=f"y_{idx}"):
                    st.session_state.user_confirmations[item_id] = "yes"
                    st.rerun()
                if col2.button("Not me", key=f"n_{idx}"):
                    st.session_state.user_confirmations[item_id] = "no"
                    st.rerun()
            st.markdown("---")

    st.markdown(f"### 📊 Report Tally")
    st.write(f"- Verified pages for report: **{len(verified)}**")
    st.write(f"- Pages excluded: **{excluded}**")

    st.divider()
    st.subheader("Download Report")
    fmt = st.selectbox("Select file format", ["PDF (.pdf)", "Word Document (.docx)", "Plain Text (.txt)"])

    if fmt == "PDF (.pdf)":
        data = generate_pdf(verified, res["name"], res["finished"])
        fname = f"IDkat_{res['name'].replace(' ', '_')}.pdf"
        mtype = "application/pdf"
    elif fmt == "Word Document (.docx)":
        data = generate_docx(verified, res["name"], res["finished"])
        fname = f"IDkat_{res['name'].replace(' ', '_')}.docx"
        mtype = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
    else:
        data = generate_txt(verified, res["name"], res["finished"])
        fname = f"IDkat_{res['name'].replace(' ', '_')}.txt"
        mtype = "text/plain"

    if st.download_button(
        label=f"📥 Download {fmt} Report & Wipe Memory",
        data=data,
        file_name=fname,
        mime=mtype,
        type="primary"
    ):
        delete_user_data(st.session_state.username)
        st.session_state.username = None
        st.success("Report downloaded and session memory wiped!")
        st.rerun()
    st.stop()

# Search Input Form
st.subheader("Configure Deep Search")
with st.form("deep_scan_form"):
    name = st.text_input("Your full name *")
    location = st.text_input("Current & past cities/regions", placeholder="e.g. Geelong, Melbourne, Sydney")

    st.markdown("---")
    st.markdown("#### Work & Professional Footprint Clues")
    workplaces = st.text_area("Workplaces, Companies & Schools (one per line)", placeholder="e.g. Acme Media\nMonash University\nTech Corp")

    st.markdown("---")
    st.markdown("#### Handles & Direct Profiles")
    usernames = st.text_input("Social handles / usernames (comma-separated)", placeholder="e.g. @willwright, @willwrightmedia")
    known_links = st.text_area("Direct profile URLs (LinkedIn, Instagram, personal site)", placeholder="https://www.linkedin.com/in/willwright\nhttps://www.instagram.com/willwright")

    st.markdown("---")
    passes = st.slider("Number of Search Passes (1 to 50)", min_value=1, max_value=50, value=10, help="Higher passes perform deeper systematic checks across corporate registers, social handles, news, and publications.")

    confirm = st.checkbox("I confirm I am searching for information about myself")
    submit = st.form_submit_button("Start Deep Search", type="primary")

if submit:
    if not name.strip() or not confirm:
        st.error("Please fill in your name and confirm you are searching for yourself.")
    else:
        clues_data = {
            "known_links": [l.strip() for l in known_links.split("\n") if l.strip()],
            "current_city": location.strip(),
            "past_cities": [c.strip() for c in location.split(",") if c.strip()],
            "workplaces_schools": [w.strip() for w in workplaces.split("\n") if w.strip()],
            "usernames": [u.strip() for u in usernames.split(",") if u.strip()],
        }

        start_deep_scan(
            st.session_state.username,
            {"name": name.strip(), "location": location.strip()},
            clues_data,
            passes
        )
        st.rerun()
