# IDkat

**Find where your personal information appears online, and how to remove it.**

IDkat is a privacy self-check. People sign in with their email, search for information about themselves across the public web, and receive a one-page summary and a full action plan by email. Their results are then deleted.

## How it works

1. **Sign in without a password.** Enter your email and tick two consent boxes. IDkat emails a one-time sign-in link (valid for 15 minutes), along with the consent notice.
2. **Search for yourself.** Enter your name, any other names, and optionally your city. IDkat searches social media, forums, blogs, people-search sites and data brokers, and other public listings. The search runs in the background: you can close the page, and IDkat emails you when your results are ready.
3. **Help IDkat rule out other people with your name.** Answer short questions about you: what you do for work, hobbies and sports you're known for, whether you're a public figure, where you've lived, worked and studied, and your usernames. You can answer before the search, while it runs, or when IDkat asks about specific pages. **Your answers never leave IDkat**: they're compared with the results privately and deleted with them.
4. **Review pages confirmed as yours.** A page only counts as yours with strong evidence: your own profile link or username, or two or more matching details and none conflicting. Pages about other people, or that can't be confirmed, are left out and never shown; you just see how many. Each confirmed page shows what *kinds* of information it exposes and how to remove it, and you can mark any as "Not me".
5. **Search again with more details** (up to twice), such as a former surname or old username. New pages are added without duplicates.
6. **Get your reports and delete everything.** One click emails you a one-page summary and a full action plan as PDFs, then deletes your results.

## Privacy and safety by design

- **Only for yourself.** Each email address can search only one name for 30 days, with daily limits, so IDkat can't be used to look up other people.
- **Your answers stay private.** Occupation, hobbies, places, workplaces, schools, usernames and profile links are only compared inside IDkat. Only your name, other names and city go to the search, plus your email or occupation if you choose.
- **Other people are left out.** Pages about people with the same name are never shown, reported or kept.
- **Where, not what.** Results and reports show *where* information appears and *how* to remove it, never the details themselves. A code-level filter also removes any addresses, phone numbers or emails that slip through.
- **Nothing kept.** Results are held in memory only and deleted as soon as reports are emailed, or after two hours. Nothing is written to disk. To prevent misuse, IDkat keeps only a scrambled fingerprint of each email and searched name, in memory, for up to 30 days.
- **Clear consent.** Users confirm they're searching for themselves and agree to how their details are processed, both on the site and in the sign-in email.

## Things to know

- **Search is done by Google's Gemini service**, so the name and details entered are processed by Google. Use a paid Gemini API plan: Google's free tier may use data to improve its products.
- **Sent emails keep copies.** If you send through Gmail, the sign-in links and reports stay in that account's Sent folder. Use a dedicated sending account and clear it regularly, or a transactional email service with message logging turned off.
- **IDkat can't guarantee completeness** or that sites will remove information. It isn't legal advice.
- **Before offering IDkat publicly, get privacy advice** and publish a privacy policy.

## Set up (GitHub and Streamlit Community Cloud)

1. Create a **private** GitHub repository (e.g. `idkat`) and upload `app.py`, `requirements.txt`, `README.md`, `.gitignore` and the `.streamlit/config.toml` file (inside a `.streamlit` folder).
2. On Streamlit Community Cloud, create a new app from that repository, with `app.py` as the main file.
3. In the app's **Secrets** settings, paste the contents of `idkat_secrets_template.toml` with your values filled in. Don't upload that template to GitHub.
4. Set `APP_URL` to your app's address, then reboot the app.
5. Test by signing in with your own email.

## Files

- `app.py`: the application
- `requirements.txt`: Python libraries
- `.streamlit/config.toml`: theme and settings
- `.gitignore`: keeps secrets out of GitHub
- `idkat_secrets_template.toml`: reference for the Secrets settings (don't upload)
