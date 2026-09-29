"""
IDkat v3.1: Persistent Session & Background Smart Search Engine

- Persistent login tokens in URL query params (prevents logouts on refresh/reload).
- Background threaded search execution (continues running if tab/window loses focus).
- 3-Pass initial sweep with interactive term refining & real-time discovery.
- PDF, Word (.docx), and Text (.txt) exports with full memory wipe on download.
"""

import datetime
import hashlib
import hmac
import html
import io
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

st.set_page_config(page_title="IDkat Smart Search", page_icon="🐾", layout="centered")

# ============================================================================
# 0. SETTINGS & CONSTANTS
# ============================================================================
DEFAULT_MODEL = "gemini-3.8-flash"
FALLBACK_MODEL = "gemini-flash-latest"
SESSION_HOURS = 12
INK, BONE, SAND, MUTED = "#14120F", "#F2EDE3", "#C6BCA9", "#8A8275"

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
# 1. MEMORY-ONLY STORE & PERSISTENT SESSION TOKENS
# ============================================================================
@st.cache_resource
def _store():
    return {
        "lock": threading.Lock(),
        "users": {},
        "jobs": {},
        "sessions": {},  # token -> username
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

def norm_url(url):
    if not url or not str(url).startswith("http"):
        return ""
    p = urlparse(str(url).strip())
    return f"{p.netloc.lower().removeprefix('www.')}{p.path.rstrip('/')}"

def model_client(api_key):
    key = re.sub(r"[^\w.\-]", "", str(api_key or "").strip())
    return genai.Client(api_key=key, vertexai=False, enterprise=False)

def create_session(username):
    token = pysecrets.token_urlsafe(24)
    with STORE["lock"]:
        STORE["sessions"][token] = {
            "username": username,
            "expiry": time.time() + (SESSION_HOURS * 3600)
        }
    st.query_params["session"] = token
    return token

def get_session_user():
    token = st.query_params.get("session")
    if not token:
        return None
    with STORE["lock"]:
        sess = STORE["sessions"].get(token)
        if sess and sess["expiry"] > time.time():
            return sess["username"]
        elif sess:
            del STORE["sessions"][token]
            st.query_params.clear()
    return None

def destroy_session():
    token = st.query_params.get("session")
    if token:
        with STORE["lock"]:
            if token in STORE["sessions"]:
                del STORE["sessions"][token]
    st.query_params.clear()

# ============================================================================
# 2. BACKGROUND SEARCH ENGINE (CONTINUES WHEN TAB IS HIDDEN)
# ============================================================================
def execute_search_pass(client, model, query_str):
    config = types.GenerateContentConfig(
        tools=[types.Tool(google_search=types.GoogleSearch())],
        temperature=0.3
    )
    prompt = f"Find public web pages, profiles, news, and directories for: {query_str}. Return key details found."

    results = []
    try:
        resp = client.models.generate_content(model=model, contents=prompt, config=config)

        sources = []
        for cand in getattr(resp, "candidates", None) or []:
            meta = getattr(cand, "grounding_metadata", None)
            for chunk in (getattr(meta, "grounding_chunks", None) or []) if meta else []:
                web = getattr(chunk, "web", None)
                if web and getattr(web, "uri", None):
                    sources.append((getattr(web, "title", "Web Page") or "Web Page", web.uri))

        text_summary = resp.text or ""

        for title, uri in sources:
            results.append({
                "site": title[:80],
                "url": uri,
                "snippet": text_summary[:300] if text_summary else "Found in public search index.",
                "query_used": query_str
            })
    except Exception:
        pass
    return results

def run_background_initial_search(job, username, name, locations, workplaces, handles, api_key, model):
    try:
        client = model_client(api_key)
        all_found = []
        seen_urls = set()

        job["progress"] = "Pass 1/3: Sweeping Social Profiles & Handles..."
        q1 = f'"{name}" ' + " ".join([f'"{h}"' for h in handles if h])
        res1 = execute_search_pass(client, model, q1)

        job["progress"] = "Pass 2/3: Sweeping Workplaces & Directorships..."
        q2 = f'"{name}" ' + " ".join([f'"{w}"' for w in workplaces if w])
        res2 = execute_search_pass(client, model, q2)

        job["progress"] = "Pass 3/3: Sweeping Locations & Public Directories..."
        q3 = f'"{name}" ' + " ".join([f'"{l}"' for l in locations if l])
        res3 = execute_search_pass(client, model, q3)

        if not (res1 or res2 or res3):
            job["progress"] = "Broad Fallback Sweep..."
            q_fallback = f'"{name}" Australia online profile directory'
            res3.extend(execute_search_pass(client, model, q_fallback))

        for item in res1 + res2 + res3:
            norm = norm_url(item["url"])
            if norm and norm not in seen_urls:
                seen_urls.add(norm)
                all_found.append(item)

        job["result"] = all_found
        job["status"] = "done"
    except Exception as e:
        job["status"] = "failed"
        job["error"] = str(e)

def start_initial_search_thread(username, name, locations, workplaces, handles, api_key, model):
    job = {
        "id": uuid.uuid4().hex[:12],
        "owner": fingerprint(username),
        "status": "running",
        "progress": "Initializing 3-pass search...",
        "started": time.time(),
        "result": None,
        "error": ""
    }
    with STORE["lock"]:
        STORE["jobs"][job["id"]] = job
    threading.Thread(
        target=run_background_initial_search,
        args=(job, username, name, locations, workplaces, handles, api_key, model),
        daemon=True
    ).start()

def get_active_job(username):
    owner = fingerprint(username)
    with STORE["lock"]:
        jobs = [j for j in STORE["jobs"].values() if j["owner"] == owner]
        return max(jobs, key=lambda x: x["started"]) if jobs else None

def delete_user_session_and_data(username):
    owner = fingerprint(username)
    with STORE["lock"]:
        for j_id in [j for j, job in STORE["jobs"].items() if job["owner"] == owner]:
            del STORE["jobs"][j_id]
        if username.lower() in STORE["users"]:
            del STORE["users"][username.lower()]
    destroy_session()

# ============================================================================
# 3. REPORT EXPORTERS
# ============================================================================
def generate_pdf(verified_items, name):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Helvetica", "B", 16)
    pdf.cell(0, 10, f"IDkat Verified Footprint: {name}", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "", 10)
    pdf.cell(0, 5, f"Generated: {datetime.datetime.now().strftime('%d %b %Y %H:%M')}", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(5)

    for item in verified_items:
        pdf.set_font("Helvetica", "B", 11)
        pdf.cell(0, 6, item['site'], new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("Helvetica", "", 9)
        pdf.multi_cell(0, 4, f"URL: {item['url']}\nSummary: {item['snippet']}\nQuery matched: {item.get('query_used', 'N/A')}\n")
        pdf.ln(2)
    return bytes(pdf.output())

def generate_docx(verified_items, name):
    doc = docx.Document()
    doc.add_heading(f"IDkat Verified Footprint: {name}", 0)
    doc.add_paragraph(f"Generated: {datetime.datetime.now().strftime('%d %b %Y %H:%M')}")

    for item in verified_items:
        doc.add_heading(item['site'], level=2)
        doc.add_paragraph(f"URL: {item['url']}")
        doc.add_paragraph(f"Summary: {item['snippet']}")
        doc.add_paragraph(f"Search query: {item.get('query_used', 'N/A')}")

    bio = io.BytesIO()
    doc.save(bio)
    return bio.getvalue()

def generate_txt(verified_items, name):
    lines = [f"IDKAT VERIFIED FOOTPRINT REPORT: {name}", f"Generated: {datetime.datetime.now().strftime('%d %b %Y %H:%M')}", "="*50, ""]
    for item in verified_items:
        lines.append(f"Site: {item['site']}")
        lines.append(f"URL: {item['url']}")
        lines.append(f"Summary: {item['snippet']}")
        lines.append(f"Query: {item.get('query_used', 'N/A')}")
        lines.append("-" * 40)
    return "\n".join(lines).encode("utf-8")

# ============================================================================
# 4. STREAMLIT INTERFACE & SESSION MANAGEMENT
# ============================================================================
st.markdown(
    f"""<style>
.stApp {{ background:{INK}; color:{BONE}; }}
.idk-band {{ background:#1A1814; border:1px solid #2C2822; padding:22px 26px; margin-bottom:16px; }}
.idk-band .eyebrow {{ font-size:0.72rem; letter-spacing:0.22em; color:{MUTED}; text-transform:uppercase; }}
.idk-band .title {{ font-size:2.2rem; color:{BONE}; font-weight:600; line-height:1.1; }}
.idk-band .sub {{ color:{SAND}; font-style:italic; margin-top:4px; }}
</style>
<div class="idk-band"><div class="eyebrow">Interactive Smart Search</div><div class="title">🐾 IDkat v3.1</div>
<div class="sub">Persistent session & background multi-pass search engine.</div></div>""",
    unsafe_allow_html=True,
)

# Restore or verify user session
current_user = get_session_user()
if current_user and "username" not in st.session_state:
    st.session_state.username = current_user

if "username" not in st.session_state:
    st.session_state.username = None
if "search_results" not in st.session_state:
    st.session_state.search_results = []
if "confirmations" not in st.session_state:
    st.session_state.confirmations = {}
if "search_terms" not in st.session_state:
    st.session_state.search_terms = []
if "user_fullname" not in st.session_state:
    st.session_state.user_fullname = ""

# Authentication
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
                    create_session(u_in.strip())
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
                            create_session(nu.strip())
                            st.rerun()
    st.stop()

top1, top2 = st.columns([3, 1])
top1.markdown(f"Signed in as **{html.escape(st.session_state.username)}**")
if top2.button("Log out"):
    destroy_session()
    st.session_state.username = None
    st.session_state.search_results = []
    st.rerun()

api_key = str(secret("GEMINI_API_KEY", "") or "")
model_name = str(secret("GEMINI_MODEL", DEFAULT_MODEL))

# Check for running background search job
active_job = get_active_job(st.session_state.username)

if active_job and active_job["status"] == "running":
    st.info(f"⏳ **Search running in background:** {active_job['progress']}  \n*You can close this tab or navigate away; the search will keep running.*")
    time.sleep(3)
    st.rerun()

if active_job and active_job["status"] == "done" and not st.session_state.search_results:
    st.session_state.search_results = active_job["result"]
    st.rerun()

# ============================================================================
# SEARCH INTERFACE & RESULTS DASHBOARD
# ============================================================================
if not st.session_state.search_results:
    st.subheader("1. Initial 3-Pass Broad Search")
    with st.form("initial_search"):
        name = st.text_input("Full Name *", placeholder="e.g. Will Wright")
        locations = st.text_input("Cities / Regions (comma separated)", placeholder="e.g. Geelong, Melbourne")
        workplaces = st.text_area("Workplaces / Companies (one per line)", placeholder="e.g. Acme Media\nMonash University")
        handles = st.text_input("Usernames / Social Handles (comma separated)", placeholder="e.g. @willwright, @willwrightmedia")
        
        confirm = st.checkbox("I confirm I am searching for information about myself")
        start_btn = st.form_submit_button("Run Initial 3-Pass Search", type="primary")

    if start_btn:
        if not name.strip() or not confirm:
            st.error("Please enter your name and confirm authorization.")
        else:
            st.session_state.user_fullname = name.strip()
            loc_list = [x.strip() for x in locations.split(",") if x.strip()]
            work_list = [x.strip() for x in workplaces.split("\n") if x.strip()]
            hand_list = [x.strip() for x in handles.split(",") if x.strip()]

            st.session_state.search_terms = [
                {"term": t, "active": True, "type": "Location"} for t in loc_list
            ] + [
                {"term": t, "active": True, "type": "Workplace"} for t in work_list
            ] + [
                {"term": t, "active": True, "type": "Handle"} for t in hand_list
            ]

            start_initial_search_thread(
                st.session_state.username,
                name.strip(),
                loc_list,
                work_list,
                hand_list,
                api_key,
                model_name
            )
            st.rerun()

else:
    # RESULTS FOUND / INTERACTIVE DASHBOARD
    st.subheader(f"Search Results ({len(st.session_state.search_results)} items found)")
    st.caption("Review candidate pages below. Click 'This is me' to include in your final report.")

    verified = []
    excluded = 0

    for idx, item in enumerate(st.session_state.search_results):
        item_id = f"item_{idx}"
        status = st.session_state.confirmations.get(item_id, None)

        if status == "yes":
            verified.append(item)
            st.success(f"✅ **{item['site']}**  \nURL: [{item['url']}]({item['url']})")
        elif status == "no":
            excluded += 1
        else:
            with st.container():
                st.warning(f"❓ **Candidate Page:** {item['site']}")
                st.write(f"**URL:** [{item['url']}]({item['url']})")
                st.caption(f"Snippet: *\"{item['snippet']}\"*")
                c1, c2 = st.columns(2)
                if c1.button("This is me", key=f"yes_{idx}"):
                    st.session_state.confirmations[item_id] = "yes"
                    st.rerun()
                if c2.button("Not me", key=f"no_{idx}"):
                    st.session_state.confirmations[item_id] = "no"
                    st.rerun()
            st.markdown("---")

    # Smart Search Refinement Section
    st.divider()
    st.subheader("2. Smart Search Refinement (1-Pass Additional Searches)")
    st.caption("Tick or untick terms to refine the next single-pass query, or add new custom terms.")

    selected_terms = []
    for term_obj in st.session_state.search_terms:
        chk = st.checkbox(
            f"[{term_obj['type']}] {term_obj['term']}",
            value=term_obj["active"],
            key=f"chk_{term_obj['term']}"
        )
        term_obj["active"] = chk
        if chk:
            selected_terms.append(term_obj["term"])

    with st.form("add_custom_term"):
        new_term = st.text_input("Add a new term to search (e.g. Maiden name, key project, board position)")
        if st.form_submit_button("Add Term"):
            if new_term.strip():
                st.session_state.search_terms.append({"term": new_term.strip(), "active": True, "type": "Custom"})
                st.rerun()

    st.markdown("#### 💬 Clarification Questions")
    st.caption("Answering these questions creates targeted single-pass searches.")
    q_col1, q_col2 = st.columns(2)
    with q_col1:
        if st.button("🔍 Search ASIC / Corporate Registers"):
            st.session_state.search_terms.append({"term": "ASIC business directorship register", "active": True, "type": "Corporate"})
            st.rerun()
    with q_col2:
        if st.button("🔍 Search Domain WHOIS & Personal Websites"):
            st.session_state.search_terms.append({"term": "domain WHOIS registration website owner", "active": True, "type": "Domain"})
            st.rerun()

    if st.button("🚀 Run 1-Pass Smart Search Now", type="primary"):
        with st.spinner("Executing targeted 1-pass Smart Search..."):
            client = model_client(api_key)
            query = f'"{st.session_state.user_fullname}" ' + " ".join([f'"{t}"' for t in selected_terms])
            new_results = execute_search_pass(client, model_name, query)

            existing_urls = {norm_url(r["url"]) for r in st.session_state.search_results}
            added_count = 0
            for nr in new_results:
                norm = norm_url(nr["url"])
                if norm and norm not in existing_urls:
                    existing_urls.add(norm)
                    st.session_state.search_results.append(nr)
                    added_count += 1
            
            if added_count > 0:
                st.success(f"Smart Search complete! Added {added_count} new candidate pages.")
            else:
                st.info("No new additional pages found with selected terms.")
            time.sleep(1)
            st.rerun()

    # Report Tally & Export
    st.divider()
    st.subheader("3. Export Verified Report")
    st.write(f"- Verified pages confirmed: **{len(verified)}**")
    st.write(f"- Candidate pages excluded: **{excluded}**")

    fmt = st.selectbox("Select file format", ["PDF (.pdf)", "Word Document (.docx)", "Plain Text (.txt)"])

    if fmt == "PDF (.pdf)":
        data = generate_pdf(verified, st.session_state.user_fullname)
        fname = f"IDkat_{st.session_state.user_fullname.replace(' ', '_')}.pdf"
        mtype = "application/pdf"
    elif fmt == "Word Document (.docx)":
        data = generate_docx(verified, st.session_state.user_fullname)
        fname = f"IDkat_{st.session_state.user_fullname.replace(' ', '_')}.docx"
        mtype = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
    else:
        data = generate_txt(verified, st.session_state.user_fullname)
        fname = f"IDkat_{st.session_state.user_fullname.replace(' ', '_')}.txt"
        mtype = "text/plain"

    if st.download_button(
        label=f"📥 Download {fmt} Report & Wipe Memory",
        data=data,
        file_name=fname,
        mime=mtype,
        type="primary"
    ):
        delete_user_session_and_data(st.session_state.username)
        st.session_state.username = None
        st.session_state.search_results = []
        st.session_state.confirmations = {}
        st.success("Report downloaded and memory wiped!")
        st.rerun()
