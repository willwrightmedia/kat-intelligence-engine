"""
IDkat: Privacy & Media Intelligence Tool with Admin Analytics

- Persistent user accounts & profile library.
- Admin dashboard (`katadmin`) with privacy-safe metrics for advertising/monetization.
- Full analytics tracking: logins, report downloads, active sessions, and churn audit logs.
- Automatic SQLite migration & database persistence across app updates.
"""

import datetime
import hashlib
import hmac
import html
import io
import json
import re
import secrets as pysecrets
import sqlite3
import time
from pathlib import Path
from urllib.parse import urlparse

import docx
import matplotlib
import requests
import streamlit as st
from fpdf import FPDF
from google import genai
from google.genai import types

st.set_page_config(page_title="IDkat", page_icon="🐾", layout="centered")

# ============================================================================
# 0. SETTINGS & CONSTANTS
# ============================================================================
DEFAULT_MODEL = "gemini-3.8-flash"
FALLBACK_MODEL = "gemini-flash-latest"
SESSION_HOURS = 168  # 7-day persistent sessions
DB_FILE = "idkat_db.sqlite"
ADMIN_USERNAME = "katadmin"
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
# 1. DATABASE SCHEMA, AUTO-MIGRATION & ANALYTICS TRACKING
# ============================================================================
def get_db():
    conn = sqlite3.connect(DB_FILE, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                salt TEXT,
                pw_hash TEXT,
                is_admin INTEGER DEFAULT 0,
                created_at REAL,
                last_login REAL
            )
        """)
        
        # Check and migrate columns for older DB schemas
        existing_cols = [row[1] for row in conn.execute("PRAGMA table_info(users)").fetchall()]
        if "is_admin" not in existing_cols:
            conn.execute("ALTER TABLE users ADD COLUMN is_admin INTEGER DEFAULT 0")
        if "last_login" not in existing_cols:
            conn.execute("ALTER TABLE users ADD COLUMN last_login REAL DEFAULT 0")

        conn.execute("""
            CREATE TABLE IF NOT EXISTS sessions (
                token TEXT PRIMARY KEY,
                username TEXT,
                expiry REAL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS user_profiles (
                profile_id TEXT PRIMARY KEY,
                username TEXT,
                profile_name TEXT,
                fullname TEXT,
                locations TEXT,
                workplaces TEXT,
                handles TEXT,
                created_at REAL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS active_workspace (
                username TEXT PRIMARY KEY,
                profile_id TEXT,
                user_fullname TEXT,
                search_results TEXT,
                confirmations TEXT,
                search_terms TEXT,
                synthesis TEXT
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS usage_analytics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT,
                event_type TEXT,
                details TEXT,
                timestamp REAL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT,
                action TEXT,
                timestamp REAL
            )
        """)
        conn.commit()

init_db()

def log_event(username, event_type, details=""):
    with get_db() as conn:
        conn.execute(
            "INSERT INTO usage_analytics (username, event_type, details, timestamp) VALUES (?, ?, ?, ?)",
            (username, event_type, details, time.time())
        )
        conn.commit()

def log_audit(username, action):
    with get_db() as conn:
        conn.execute(
            "INSERT INTO audit_logs (username, action, timestamp) VALUES (?, ?, ?)",
            (username, action, time.time())
        )
        conn.commit()

def hash_password(password: str, salt: bytes = None) -> tuple[str, str]:
    if salt is None:
        salt = pysecrets.token_bytes(16)
    pw_hash = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 100_000)
    return salt.hex(), pw_hash.hex()

def verify_password(password: str, salt_hex: str, pw_hash_hex: str) -> bool:
    salt = bytes.fromhex(salt_hex)
    _, new_hash = hash_password(password, salt)
    return hmac.compare_digest(new_hash, pw_hash_hex)

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
    expiry = time.time() + (SESSION_HOURS * 3600)
    with get_db() as conn:
        conn.execute("INSERT OR REPLACE INTO sessions VALUES (?, ?, ?)", (token, username, expiry))
        conn.execute("UPDATE users SET last_login = ? WHERE username = ?", (time.time(), username))
        conn.commit()
    st.query_params["session"] = token
    log_event(username, "session_created")
    return token

def get_session_user():
    token = st.query_params.get("session")
    if not token:
        return None
    with get_db() as conn:
        row = conn.execute("SELECT username, expiry FROM sessions WHERE token = ?", (token,)).fetchone()
        if row:
            if row["expiry"] > time.time():
                return row["username"]
            else:
                conn.execute("DELETE FROM sessions WHERE token = ?", (token,))
                conn.commit()
                st.query_params.clear()
    return None

def destroy_session():
    token = st.query_params.get("session")
    if token:
        with get_db() as conn:
            conn.execute("DELETE FROM sessions WHERE token = ?", (token,))
            conn.commit()
    st.query_params.clear()

# Profile Management
def save_profile(username, profile_name, fullname, locations, workplaces, handles):
    profile_id = pysecrets.token_hex(8)
    with get_db() as conn:
        conn.execute(
            "INSERT INTO user_profiles VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (profile_id, username, profile_name, fullname, locations, workplaces, handles, time.time())
        )
        conn.commit()
    log_event(username, "profile_created", f"Name: {profile_name}")
    return profile_id

def get_user_profiles(username):
    with get_db() as conn:
        return conn.execute("SELECT * FROM user_profiles WHERE username = ? ORDER BY created_at DESC", (username,)).fetchall()

def delete_profile(profile_id):
    with get_db() as conn:
        conn.execute("DELETE FROM user_profiles WHERE profile_id = ?", (profile_id,))
        conn.commit()

# Workspace Management
def save_workspace(username, profile_id, fullname, results, confirmations, terms, synthesis=""):
    with get_db() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO active_workspace VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                username,
                profile_id,
                fullname,
                json.dumps(results),
                json.dumps(confirmations),
                json.dumps(terms),
                synthesis,
            )
        )
        conn.commit()

def load_workspace(username):
    with get_db() as conn:
        row = conn.execute("SELECT * FROM active_workspace WHERE username = ?", (username,)).fetchone()
        if row:
            return {
                "profile_id": row["profile_id"],
                "fullname": row["user_fullname"],
                "results": json.loads(row["search_results"]),
                "confirmations": json.loads(row["confirmations"]),
                "terms": json.loads(row["search_terms"]),
                "synthesis": row["synthesis"] if "synthesis" in row.keys() else "",
            }
    return None

def clear_workspace(username):
    with get_db() as conn:
        conn.execute("DELETE FROM active_workspace WHERE username = ?", (username,))
        conn.commit()

def delete_entire_account(username):
    log_audit(username, "account_deleted")
    with get_db() as conn:
        conn.execute("DELETE FROM users WHERE username = ?", (username,))
        conn.execute("DELETE FROM user_profiles WHERE username = ?", (username,))
        conn.execute("DELETE FROM active_workspace WHERE username = ?", (username,))
        conn.execute("DELETE FROM sessions WHERE username = ?", (username,))
        conn.commit()
    destroy_session()

# ============================================================================
# 2. SEARCH & SYNTHESIS ENGINE
# ============================================================================
def execute_search_pass(client, model, query_str):
    config = types.GenerateContentConfig(
        tools=[types.Tool(google_search=types.GoogleSearch())],
        temperature=0.3
    )
    prompt = f"Find public web pages, social profiles, directories, and news for: {query_str}. List exact sites and URLs found."

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

def run_3_pass_search(name, locations, workplaces, handles, api_key, model):
    client = model_client(api_key)
    all_found = []
    seen_urls = set()

    progress_bar = st.progress(0, text="Starting 3-Pass Search...")

    progress_bar.progress(20, text="Pass 1/3: Checking social profiles and handles...")
    q1 = f'"{name}" ' + " ".join([f'"{h}"' for h in handles if h])
    res1 = execute_search_pass(client, model, q1)

    progress_bar.progress(50, text="Pass 2/3: Checking workplaces and business records...")
    q2 = f'"{name}" ' + " ".join([f'"{w}"' for w in workplaces if w])
    res2 = execute_search_pass(client, model, q2)

    progress_bar.progress(80, text="Pass 3/3: Checking cities and regional listings...")
    q3 = f'"{name}" ' + " ".join([f'"{l}"' for l in locations if l])
    res3 = execute_search_pass(client, model, q3)

    if not (res1 or res2 or res3):
        progress_bar.progress(90, text="Running fallback profile search...")
        q_fallback = f'"{name}" online profile'
        res3.extend(execute_search_pass(client, model, q_fallback))

    progress_bar.progress(100, text="Search Complete!")
    time.sleep(0.5)
    progress_bar.empty()

    for item in res1 + res2 + res3:
        norm = norm_url(item["url"])
        if norm and norm not in seen_urls:
            seen_urls.add(norm)
            all_found.append(item)

    return all_found

def synthesize_report_intelligence(name, verified_items, api_key, model):
    client = model_client(api_key)
    item_context = "\n".join([f"- Site: {i['site']} | URL: {i['url']} | Context: {i['snippet']}" for i in verified_items])

    prompt = f"""You are a media intelligence and privacy compliance analyst. Analyze the following verified online web findings for person: "{name}".

FINDINGS:
{item_context}

Provide a structured, executive-level intelligence synthesis with 4 sections:
1. EXECUTIVE SUMMARY & PUBLIC FOOTPRINT NARRATIVE: What does this collection of information convey about the person's professional and public persona?
2. PRIVACY & EXPOSURE RISKS: Are there any specific privacy, safety, or identity risks (e.g. historical affiliations, contact info leakage, profile mixing)?
3. RECOMMENDED ACTIONS: Bullet points on specific steps to take (e.g. content removal requests, privacy setting toggles, account closures).
4. STRATEGIC RECOMMENDATIONS: Forward-looking advice to protect digital footprint and manage online reputation.

Keep the language professional, direct, and actionable."""

    try:
        resp = client.models.generate_content(model=model, contents=prompt)
        return resp.text or "Synthesis could not be generated."
    except Exception as e:
        return f"Synthesis error: {str(e)}"

# ============================================================================
# 3. UNICODE SAFE REPORT EXPORTERS
# ============================================================================
def clean_pdf_text(text):
    if not text:
        return ""
    replacements = {
        "“": '"', "”": '"', "‘": "'", "’": "'",
        "—": "-", "–": "-", "…": "...", "•": "*",
        "\u200b": "", "\xa0": " "
    }
    for k, v in replacements.items():
        text = text.replace(k, v)
    return text.encode("latin-1", "replace").decode("latin-1")

def generate_pdf(verified_items, name, synthesis=""):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Helvetica", "B", 16)
    pdf.cell(0, 10, clean_pdf_text(f"IDkat Media & Privacy Intelligence Report: {name}"), new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "", 10)
    pdf.cell(0, 5, clean_pdf_text(f"Generated: {datetime.datetime.now().strftime('%d %b %Y %H:%M')}"), new_x="LMARGIN", new_y="NEXT")
    pdf.ln(5)

    if synthesis:
        pdf.set_font("Helvetica", "B", 12)
        pdf.cell(0, 8, clean_pdf_text("INTELLIGENCE SYNTHESIS & RISK ANALYSIS"), new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("Helvetica", "", 9)
        pdf.multi_cell(0, 4, clean_pdf_text(synthesis))
        pdf.ln(5)

    pdf.set_font("Helvetica", "B", 12)
    pdf.cell(0, 8, clean_pdf_text("VERIFIED PAGES & FOOTPRINT DETAILS"), new_x="LMARGIN", new_y="NEXT")
    for item in verified_items:
        pdf.set_font("Helvetica", "B", 10)
        pdf.cell(0, 6, clean_pdf_text(item['site']), new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("Helvetica", "", 9)
        details = f"URL: {item['url']}\nSummary: {item['snippet']}\nQuery: {item.get('query_used', 'N/A')}\n"
        pdf.multi_cell(0, 4, clean_pdf_text(details))
        pdf.ln(2)
    return bytes(pdf.output())

def generate_docx(verified_items, name, synthesis=""):
    doc = docx.Document()
    doc.add_heading(f"IDkat Media & Privacy Intelligence Report: {name}", 0)
    doc.add_paragraph(f"Generated: {datetime.datetime.now().strftime('%d %b %Y %H:%M')}")

    if synthesis:
        doc.add_heading("Intelligence Synthesis & Risk Analysis", level=1)
        doc.add_paragraph(synthesis)

    doc.add_heading("Verified Pages & Footprint Details", level=1)
    for item in verified_items:
        doc.add_heading(item['site'], level=2)
        doc.add_paragraph(f"URL: {item['url']}")
        doc.add_paragraph(f"Summary: {item['snippet']}")
        doc.add_paragraph(f"Search Query: {item.get('query_used', 'N/A')}")

    bio = io.BytesIO()
    doc.save(bio)
    return bio.getvalue()

def generate_txt(verified_items, name, synthesis=""):
    lines = [f"IDKAT MEDIA & PRIVACY INTELLIGENCE REPORT: {name}", f"Generated: {datetime.datetime.now().strftime('%d %b %Y %H:%M')}", "="*60, ""]
    if synthesis:
        lines.append("INTELLIGENCE SYNTHESIS & RISK ANALYSIS:")
        lines.append(synthesis)
        lines.append("\n" + "="*60 + "\n")

    lines.append("VERIFIED PAGES & FOOTPRINT DETAILS:")
    for item in verified_items:
        lines.append(f"Site: {item['site']}")
        lines.append(f"URL: {item['url']}")
        lines.append(f"Summary: {item['snippet']}")
        lines.append(f"Query: {item.get('query_used', 'N/A')}")
        lines.append("-" * 40)
    return "\n".join(lines).encode("utf-8")

# ============================================================================
# 4. STREAMLIT INTERFACE & ADMIN DASHBOARD
# ============================================================================
st.markdown(
    f"""<style>
.stApp {{ background:{INK}; color:{BONE}; }}
.idk-band {{ background:#1A1814; border:1px solid #2C2822; padding:22px 26px; margin-bottom:16px; }}
.idk-band .eyebrow {{ font-size:0.72rem; letter-spacing:0.22em; color:{MUTED}; text-transform:uppercase; }}
.idk-band .title {{ font-size:2.2rem; color:{BONE}; font-weight:600; line-height:1.1; }}
.idk-band .sub {{ color:{SAND}; font-style:normal; margin-top:6px; font-size:1.0rem; }}
</style>
<div class="idk-band">
  <div class="eyebrow">Privacy & Media Intelligence Tool</div>
  <div class="title">🐾 IDkat</div>
  <div class="sub">Find where your personal information appears online, review what's exposed, and export a synthesized intelligence report. All your data is retained in your account library.</div>
</div>""",
    unsafe_allow_html=True,
)

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
if "synthesis" not in st.session_state:
    st.session_state.synthesis = ""
if "selected_profile_id" not in st.session_state:
    st.session_state.selected_profile_id = ""

if st.session_state.username and not st.session_state.search_results:
    db_state = load_workspace(st.session_state.username)
    if db_state:
        st.session_state.selected_profile_id = db_state.get("profile_id", "")
        st.session_state.user_fullname = db_state["fullname"]
        st.session_state.search_results = db_state["results"]
        st.session_state.confirmations = db_state["confirmations"]
        st.session_state.search_terms = db_state["terms"]
        st.session_state.synthesis = db_state.get("synthesis", "")

# Authentication View
if not st.session_state.username:
    tab1, tab2 = st.tabs(["Sign In", "Create Account"])
    
    with tab1:
        with st.form("login"):
            u_in = st.text_input("Username")
            p_in = st.text_input("Password", type="password")
            if st.form_submit_button("Sign In", type="primary"):
                u_clean = u_in.strip().lower()
                with get_db() as conn:
                    user_row = conn.execute("SELECT * FROM users WHERE username = ?", (u_clean,)).fetchone()
                if user_row and verify_password(p_in, user_row["salt"], user_row["pw_hash"]):
                    st.session_state.username = user_row["username"]
                    create_session(user_row["username"])
                    log_event(user_row["username"], "login_success")
                    st.rerun()
                else:
                    st.error("Invalid username or password.")

    with tab2:
        with st.form("signup"):
            nu = st.text_input("Choose Username")
            np = st.text_input("Choose Password", type="password")
            if st.form_submit_button("Create Account", type="primary"):
                if nu and np:
                    u_clean = nu.strip().lower()
                    is_admin_user = 1 if u_clean == ADMIN_USERNAME else 0
                    with get_db() as conn:
                        existing = conn.execute("SELECT username FROM users WHERE username = ?", (u_clean,)).fetchone()
                        if existing:
                            st.error("Username taken. Please choose another.")
                        else:
                            s, h = hash_password(np)
                            conn.execute(
                                "INSERT INTO users (username, salt, pw_hash, is_admin, created_at, last_login) VALUES (?, ?, ?, ?, ?, ?)",
                                (u_clean, s, h, is_admin_user, time.time(), time.time())
                            )
                            conn.commit()
                            st.session_state.username = u_clean
                            create_session(u_clean)
                            log_event(u_clean, "account_created")
                            st.success("Account created!")
                            time.sleep(0.5)
                            st.rerun()
                else:
                    st.error("Please fill in both fields.")
    st.stop()

# Check Admin Status
is_admin = (st.session_state.username.lower() == ADMIN_USERNAME)

# Sidebar
with st.sidebar:
    st.title("👤 Account")
    st.write(f"Logged in: **{st.session_state.username}** {'(Admin)' if is_admin else ''}")
    
    if st.button("Log out", width="stretch"):
        destroy_session()
        st.session_state.username = None
        st.session_state.search_results = []
        st.rerun()

    if not is_admin:
        st.divider()
        st.subheader("📁 Profile Library")
        saved_profiles = get_user_profiles(st.session_state.username)
        
        if saved_profiles:
            for p in saved_profiles:
                st.markdown(f"**{p['profile_name']}** ({p['fullname']})")
                col_p1, col_p2 = st.columns([3, 1])
                if col_p1.button("Load Profile", key=f"load_{p['profile_id']}"):
                    st.session_state.selected_profile_id = p["profile_id"]
                    st.session_state.user_fullname = p["fullname"]
                    st.session_state.search_results = []
                    st.session_state.confirmations = {}
                    st.session_state.synthesis = ""
                    st.rerun()
                if col_p2.button("🗑️", key=f"del_{p['profile_id']}"):
                    delete_profile(p["profile_id"])
                    st.rerun()
                st.markdown("---")
        else:
            st.caption("No saved profiles in your library yet.")

        st.divider()
        with st.expander("Danger Zone"):
            if st.button("Delete My Account & All Data", type="primary"):
                delete_entire_account(st.session_state.username)
                st.session_state.username = None
                st.session_state.search_results = []
                st.rerun()

api_key = str(secret("GEMINI_API_KEY", "") or "")
model_name = str(secret("GEMINI_MODEL", DEFAULT_MODEL))

# ============================================================================
# ADMIN PANEL VIEW (Only visible to katadmin)
# ============================================================================
if is_admin:
    st.subheader("⚙️ Admin Analytics & User Management")
    st.caption("Platform analytics and privacy-safe user metrics for media & advertiser insights.")

    tab_a1, tab_a2, tab_a3 = st.tabs(["📊 Analytics & Media Metrics", "👥 User List & Sessions", "💾 Database Backup"])

    with get_db() as conn:
        total_users = conn.execute("SELECT COUNT(*) FROM users WHERE is_admin = 0").fetchone()[0]
        active_sessions = conn.execute("SELECT COUNT(*) FROM sessions WHERE expiry > ?", (time.time(),)).fetchone()[0]
        total_searches = conn.execute("SELECT COUNT(*) FROM usage_analytics WHERE event_type = 'search_run'").fetchone()[0]
        total_reports = conn.execute("SELECT COUNT(*) FROM usage_analytics WHERE event_type = 'report_downloaded'").fetchone()[0]

    with tab_a1:
        st.markdown("#### Platform KPI Summary")
        m1, m2, m3, m4 = st.columns(4)
        m1.metric("Registered Users", total_users)
        m2.metric("Active Sessions", active_sessions)
        m3.metric("Searches Executed", total_searches)
        m4.metric("Reports Generated", total_reports)

        st.divider()
        st.markdown("#### 🎯 Aggregated Demographic & Regional Reach (For Advertisers)")
        st.caption("Aggregated locations extracted from saved profiles without identifying individual users.")
        
        with get_db() as conn:
            loc_rows = conn.execute("SELECT locations FROM user_profiles WHERE locations != ''").fetchall()
        
        all_locs = []
        for r in loc_rows:
            all_locs.extend([l.strip().title() for l in r["locations"].split(",") if l.strip()])
        
        if all_locs:
            from collections import Counter
            counts = Counter(all_locs).most_common(10)
            st.write("**Top Target Audience Regions:**")
            for loc, count in counts:
                st.markdown(f"- **{loc}**: {count} profile(s)")
        else:
            st.info("No location demographic data compiled yet.")

    with tab_a2:
        st.markdown("#### User Accounts Audit")
        with get_db() as conn:
            user_list = conn.execute("SELECT username, created_at, last_login FROM users WHERE is_admin = 0 ORDER BY created_at DESC").fetchall()
        
        if user_list:
            u_data = []
            for u in user_list:
                joined_ts = datetime.datetime.fromtimestamp(u["created_at"]).strftime("%d %b %Y %H:%M") if u["created_at"] else "N/A"
                login_ts = datetime.datetime.fromtimestamp(u["last_login"]).strftime("%d %b %Y %H:%M") if u["last_login"] else "N/A"
                u_data.append({
                    "Username": u["username"],
                    "Joined": joined_ts,
                    "Last Active": login_ts,
                })
            st.dataframe(u_data, width="stretch")
        else:
            st.info("No registered users yet.")

        st.divider()
        st.markdown("#### Account Churn Audit Log")
        with get_db() as conn:
            audit_list = conn.execute("SELECT username, action, timestamp FROM audit_logs ORDER BY timestamp DESC LIMIT 20").fetchall()
        
        if audit_list:
            a_data = [{
                "Username": a["username"],
                "Action": a["action"],
                "Timestamp": datetime.datetime.fromtimestamp(a["timestamp"]).strftime("%d %b %Y %H:%M")
            } for a in audit_list]
            st.dataframe(a_data, width="stretch")

    with tab_a3:
        st.markdown("#### Database Backup & Deployment Safeguard")
        st.caption("Download a copy of the SQLite database before pushing code updates to GitHub or Streamlit Cloud.")
        
        if Path(DB_FILE).exists():
            with open(DB_FILE, "rb") as f:
                db_bytes = f.read()
            st.download_button(
                label="📥 Download Complete Database Backup (.sqlite)",
                data=db_bytes,
                file_name=f"idkat_db_backup_{datetime.datetime.now().strftime('%Y%m%d_%H%M')}.sqlite",
                mime="application/x-sqlite3",
                type="primary"
            )

    st.stop()

# ============================================================================
# REGULAR USER DASHBOARD
# ============================================================================
if not st.session_state.search_results:
    st.subheader("1. Start Your Search / Save Profile")
    with st.form("initial_search"):
        profile_label = st.text_input("Profile Name (to save in your library)", value="My Primary Profile", placeholder="e.g. Personal Profile, Professional Alias")
        name = st.text_input("Full Name *", placeholder="e.g. Will Wright")
        locations = st.text_input("Cities / Towns lived in", placeholder="e.g. Geelong, Melbourne")
        workplaces = st.text_area("Workplaces / Companies / Schools", placeholder="e.g. Acme Media\nMonash University")
        handles = st.text_input("Social Media Handles / Usernames", placeholder="e.g. @willwright, @willwrightmedia")
        
        save_to_lib = st.checkbox("Save this profile to my library for future runs", value=True)
        confirm = st.checkbox("I confirm I am searching for information about myself")
        start_btn = st.form_submit_button("Run 3-Pass Search", type="primary")

    if start_btn:
        if not name.strip() or not confirm:
            st.error("Please enter your name and confirm you are searching for yourself.")
        else:
            st.session_state.user_fullname = name.strip()
            loc_list = [x.strip() for x in locations.split(",") if x.strip()]
            work_list = [x.strip() for x in workplaces.split("\n") if x.strip()]
            hand_list = [x.strip() for x in handles.split(",") if x.strip()]

            if save_to_lib:
                pid = save_profile(
                    st.session_state.username,
                    profile_label.strip() or "Saved Profile",
                    name.strip(),
                    locations.strip(),
                    workplaces.strip(),
                    handles.strip()
                )
                st.session_state.selected_profile_id = pid

            st.session_state.search_terms = [
                {"term": t, "active": True, "type": "Location"} for t in loc_list
            ] + [
                {"term": t, "active": True, "type": "Workplace"} for t in work_list
            ] + [
                {"term": t, "active": True, "type": "Handle"} for t in hand_list
            ]

            results = run_3_pass_search(
                name.strip(),
                loc_list,
                work_list,
                hand_list,
                api_key,
                model_name
            )
            st.session_state.search_results = results
            save_workspace(
                st.session_state.username,
                st.session_state.selected_profile_id,
                st.session_state.user_fullname,
                st.session_state.search_results,
                st.session_state.confirmations,
                st.session_state.search_terms,
                st.session_state.synthesis,
            )
            log_event(st.session_state.username, "search_run")
            st.rerun()

else:
    st.subheader(f"Search Results ({len(st.session_state.search_results)} pages found)")
    st.caption("Review candidate pages below. Click 'This is me' to include a page in your synthesized report.")

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
                st.caption(f"Summary: *\"{item['snippet']}\"*")
                c1, c2 = st.columns(2)
                if c1.button("This is me", key=f"yes_{idx}"):
                    st.session_state.confirmations[item_id] = "yes"
                    save_workspace(
                        st.session_state.username,
                        st.session_state.selected_profile_id,
                        st.session_state.user_fullname,
                        st.session_state.search_results,
                        st.session_state.confirmations,
                        st.session_state.search_terms,
                        st.session_state.synthesis,
                    )
                    st.rerun()
                if c2.button("Not me", key=f"no_{idx}"):
                    st.session_state.confirmations[item_id] = "no"
                    save_workspace(
                        st.session_state.username,
                        st.session_state.selected_profile_id,
                        st.session_state.user_fullname,
                        st.session_state.search_results,
                        st.session_state.confirmations,
                        st.session_state.search_terms,
                        st.session_state.synthesis,
                    )
                    st.rerun()
            st.markdown("---")

    # Synthesis Section
    st.divider()
    st.subheader("2. Media & Privacy Intelligence Synthesis")
    if verified:
        if st.button("🧠 Synthesize Findings into Intelligence Report", type="primary"):
            with st.spinner("Analyzing verified pages, evaluating risks, and writing recommendations..."):
                st.session_state.synthesis = synthesize_report_intelligence(
                    st.session_state.user_fullname, verified, api_key, model_name
                )
                save_workspace(
                    st.session_state.username,
                    st.session_state.selected_profile_id,
                    st.session_state.user_fullname,
                    st.session_state.search_results,
                    st.session_state.confirmations,
                    st.session_state.search_terms,
                    st.session_state.synthesis,
                )
                log_event(st.session_state.username, "report_synthesized")
                st.rerun()

        if st.session_state.synthesis:
            st.markdown(st.session_state.synthesis)
    else:
        st.info("Mark at least one candidate page as 'This is me' above to synthesize your report.")

    # Smart Search Refinement
    st.divider()
    st.subheader("3. Refine Search")
    st.caption("Tick or untick details below to refine your next single-pass search, or add custom terms.")

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
        new_term = st.text_input("Add another detail to search (e.g. Maiden name, project name, board role)")
        if st.form_submit_button("Add Detail"):
            if new_term.strip():
                st.session_state.search_terms.append({"term": new_term.strip(), "active": True, "type": "Custom"})
                save_workspace(
                    st.session_state.username,
                    st.session_state.selected_profile_id,
                    st.session_state.user_fullname,
                    st.session_state.search_results,
                    st.session_state.confirmations,
                    st.session_state.search_terms,
                    st.session_state.synthesis,
                )
                st.rerun()

    st.markdown("#### Quick Narrow-Down Prompts")
    q_col1, q_col2 = st.columns(2)
    with q_col1:
        if st.button("🔍 Check Business & ASIC Registers"):
            st.session_state.search_terms.append({"term": "ASIC business directorship register", "active": True, "type": "Corporate"})
            save_workspace(
                st.session_state.username,
                st.session_state.selected_profile_id,
                st.session_state.user_fullname,
                st.session_state.search_results,
                st.session_state.confirmations,
                st.session_state.search_terms,
                st.session_state.synthesis,
            )
            st.rerun()
    with q_col2:
        if st.button("🔍 Check Website Registrations"):
            st.session_state.search_terms.append({"term": "domain WHOIS registration website owner", "active": True, "type": "Domain"})
            save_workspace(
                st.session_state.username,
                st.session_state.selected_profile_id,
                st.session_state.user_fullname,
                st.session_state.search_results,
                st.session_state.confirmations,
                st.session_state.search_terms,
                st.session_state.synthesis,
            )
            st.rerun()

    if st.button("🚀 Run 1-Pass Search Extension"):
        with st.spinner("Searching for additional pages..."):
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
            
            save_workspace(
                st.session_state.username,
                st.session_state.selected_profile_id,
                st.session_state.user_fullname,
                st.session_state.search_results,
                st.session_state.confirmations,
                st.session_state.search_terms,
                st.session_state.synthesis,
            )
            if added_count > 0:
                st.success(f"Search updated! Found {added_count} new candidate pages.")
            else:
                st.info("No additional new pages found with those terms.")
            time.sleep(0.5)
            st.rerun()

    st.divider()
    st.subheader("4. Export Report")
    st.write(f"- Pages verified for report: **{len(verified)}**")
    st.write(f"- Pages excluded: **{excluded}**")

    fmt = st.selectbox("Select file format", ["PDF (.pdf)", "Word Document (.docx)", "Plain Text (.txt)"])

    if fmt == "PDF (.pdf)":
        data = generate_pdf(verified, st.session_state.user_fullname, st.session_state.synthesis)
        fname = f"IDkat_Intelligence_Report_{st.session_state.user_fullname.replace(' ', '_')}.pdf"
        mtype = "application/pdf"
    elif fmt == "Word Document (.docx)":
        data = generate_docx(verified, st.session_state.user_fullname, st.session_state.synthesis)
        fname = f"IDkat_Intelligence_Report_{st.session_state.user_fullname.replace(' ', '_')}.docx"
        mtype = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
    else:
        data = generate_txt(verified, st.session_state.user_fullname, st.session_state.synthesis)
        fname = f"IDkat_Intelligence_Report_{st.session_state.user_fullname.replace(' ', '_')}.txt"
        mtype = "text/plain"

    if st.download_button(
        label=f"📥 Download {fmt} Report & Clear Active Search",
        data=data,
        file_name=fname,
        mime=mtype,
        type="primary"
    ):
        clear_workspace(st.session_state.username)
        log_event(st.session_state.username, "report_downloaded", f"Format: {fmt}")
        st.session_state.search_results = []
        st.session_state.confirmations = {}
        st.session_state.synthesis = ""
        st.success("Report downloaded! Active search session cleared (your account and saved profiles remain in your library).")
        st.rerun()
