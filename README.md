# IDkat

**Find where your personal information appears online, and how to remove it.**

IDkat is a privacy self-check. People sign in with their email, search for information about themselves across the public web, and receive a one-page summary and a full action plan by email. Their results are then deleted.

## How it works

1. **Sign in without a password.** Enter your email and tick two consent boxes. IDkat emails a one-time sign-in link (valid for 15 minutes), along with the consent notice.
2. **Search for yourself.** Enter your name, any other names or usernames, and optionally your city. IDkat searches social media, forums, blogs, people-search sites and data brokers, and other public listings. The search runs in the background: you can close the page, and IDkat emails you when your results are ready.
3. **Review your results.** Each page found shows what *kinds* of information it exposes (e.g. home address, phone number, photos), whether it's likely you or someone with the same name, and how to remove or hide it.
4. **Get your reports and delete everything.** One click emails you a one-page summary and a full action plan as PDFs, then deletes your results.

## Privacy and safety by design

- **Only for yourself.** Each email address can search only one name for 30 days, with daily limits, so IDkat can't be used to look up other people.
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
