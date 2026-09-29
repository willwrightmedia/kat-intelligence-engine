# IDkat

**Find where your personal information appears online, and how to remove it. Free, supported by sponsors.**

IDkat is a privacy self-check. People create a free account, search for information about themselves, and keep the resulting reports in a private library. Sponsors support the app through clearly labelled messages, without ever receiving anything about users.

## For users

1. **Create a free account** with a username, password and email address. A 6-digit code is emailed to verify the address. You're shown a **recovery code** once: it's the only way to keep your saved reports if you forget your password.
2. **Search for yourself.** Enter your name, other names and (optionally) your city. The search covers social media, forums, blogs, people-search and data-broker sites, and other public listings, and runs in the background.
3. **Help IDkat rule out other people with your name** by answering short questions about you: work, hobbies and sports, whether you're a public figure, where you've lived, worked and studied, and your usernames. **Your answers never leave IDkat.**
4. **Review pages confirmed as yours.** Only pages with strong evidence count: your own profile link or username, or two or more matching details and none conflicting. Pages about other people are never shown. You can mark any page "Not me", and search again with extra details (up to twice).
5. **Save your report** to your library (a one-page summary and a full action plan), with an optional email copy. Your search results and answers are then deleted.
6. **Manage your account:** change your password, make a new recovery code, or close your account (which deletes your reports straight away).

## Privacy design

- **Reports are encrypted with each user's own key** (AES-256). The key is stored only in locked form: locked with the user's password, with their recovery code, and, while they're signed in, with their session. The database holds only scrambled reports, so the administrator, and anyone who can read the database, can't open them.
- **Email addresses are never stored**, only a scrambled fingerprint (used to verify accounts and reset passwords).
- **Search answers never leave IDkat.** Only the name, other names and city are sent to the search (plus email or occupation if the user chooses).
- **Other people with the same name are left out**: never shown, reported or kept.
- **One name per account for 30 days**, with daily limits, so IDkat can't be used to look up others.
- **The administrator sees usernames and usage only**: account opening and closing dates, sessions (times and lengths), searches and reports saved. Never names, searches, answers or reports.
- **Sponsors get combined statistics only**, never individual records. Sponsored messages use no tracking scripts, cookies or remote images; views and clicks are counted inside IDkat.

**Honest limits:** encryption happens on the server, so it protects stored data, not a deliberately altered app. A user who loses both their password and recovery code loses their saved reports. Searches are processed by Google's Gemini service: use a paid Gemini plan, since the free tier may use data to improve Google's products.

## For the administrator (katadmin)

Sign in as `katadmin` to see:
- **Overview:** active accounts, active users, searches and reports, sessions by hour and day of week, and new accounts by week.
- **Users:** each username with account opened and closed dates, sessions, total time, searches, reports saved and last active, plus recent sessions. Downloadable as CSV (for your own use: it includes usernames).
- **For advertisers:** combined statistics with no usernames (active users, sessions, session length, returning users, busiest times, sponsor performance). Downloadable as CSV and safe to share with sponsors.
- **Sponsors:** add, pause or delete sponsored messages (name, headline, short message, link, optional image), and see views and clicks.

## Before launching publicly

- **Get privacy advice and publish a privacy policy.** As we understand it, Australia's small-business exemption from the Privacy Act doesn't cover businesses that trade in personal information, so keep advertiser sharing to combined statistics, as IDkat does.
- **Label sponsored content clearly** (IDkat does) and check your obligations under consumer law.
- Check the current terms of Google's Gemini API and your email provider.

## Setup

### 1. Create the database (Supabase, free)
1. Sign up at supabase.com and create a new project. Choose the **Sydney** region and set a strong database password (keep it: you'll need it below).
2. In the project, open **Connect** (or **Project Settings → Database**) and find the connection string for the **session pooler** (it looks like `postgresql://postgres.xxxx:[YOUR-PASSWORD]@aws-0-ap-southeast-2.pooler.supabase.com:5432/postgres`). Supabase's menus change from time to time, so the exact labels may differ.
3. Build your connection line: change `postgresql://` to `postgresql+psycopg2://`, put your database password in place of `[YOUR-PASSWORD]`, and add `?sslmode=require` to the end.
4. IDkat creates its tables automatically the first time it runs.

Note: free Supabase projects pause after about a week without use. Open the Supabase dashboard to restore it if that happens, or use a paid plan once IDkat has regular users.

### 2. Put the app on GitHub and Streamlit
1. Create a **private** GitHub repository (e.g. `idkat`) and upload `app.py`, `requirements.txt`, `README.md`, `.gitignore`, and `config.toml` inside a `.streamlit` folder.
2. On Streamlit Community Cloud, create an app from the repository, with `app.py` as the main file.
3. In the app's **Secrets**, paste the contents of `idkat_secrets_template.toml` with your values, including the database line under `[connections.idkat_db]`. Leave out `KATADMIN_PASSWORD_HASH` for now.
4. Reboot the app. On the **Sign in** tab, open **Administrator setup**, create your katadmin password, and paste the line it shows into Secrets. Reboot again.
5. Test: create a user account with your own email, run a search, save a report, and sign in as katadmin to see the console.

Without the database line, IDkat still runs, but uses a temporary file that Streamlit deletes when the app restarts (the admin console shows a warning).

## Files

- `app.py`: the application
- `requirements.txt`: Python libraries
- `.streamlit/config.toml`: theme and settings
- `.gitignore`: keeps secrets and local files out of GitHub
- `idkat_secrets_template.toml`: reference for Secrets (don't upload)
