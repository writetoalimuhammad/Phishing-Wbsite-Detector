# 🛡️ AI Phishing URL Detector

A Streamlit web app that checks whether a URL looks like phishing. It combines
**rule-based checks** (IP hosts, look-alike domains, odd TLDs, brand impersonation,
shorteners, etc.) with **Google Gemini Flash** analysis, then shows one verdict:
**Legitimate**, **Suspicious**, or **Phishing**, with a risk percentage and reasons.

The app only analyses the URL *text*. It never opens the link.

## Features
- Verdict + risk score + plain-language reasons
- Works without AI too (rule-based fallback if no key or Gemini fails)
- Handles missing `https://`, malformed URLs and unusual input

## Run locally
```bash
pip install -r requirements.txt
export GEMINI_API_KEY="your_key_here"      # Windows PowerShell: $env:GEMINI_API_KEY="your_key_here"
streamlit run app.py
```
Get a free key at https://aistudio.google.com/apikey. You can also paste the key into the
app sidebar instead of setting the variable.

## Configuration
| Name | Purpose | Default |
|------|---------|---------|
| `GEMINI_API_KEY` | Your Gemini API key | none |
| `GEMINI_MODEL` | Gemini model name | `gemini-2.5-flash` |

Set these as environment variables or in Streamlit secrets.

## Deploy on Streamlit Community Cloud
1. Push this repo to GitHub.
2. Go to https://share.streamlit.io and sign in with GitHub.
3. Click **Create app**, pick your repo, branch `main`, main file `app.py`.
4. Open **Advanced settings → Secrets** and add:
   ```toml
   GEMINI_API_KEY = "your_key_here"
   ```
5. Click **Deploy**.

## Limitations
No detector is perfect. A "legitimate" result is not a guarantee, and new phishing sites
can slip through. Never enter passwords on a link you are unsure about.
