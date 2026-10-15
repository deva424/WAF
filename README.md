# ClearGate URL Risk Scanner

ClearGate is a small web application for screening a submitted URL with a
pre-trained machine-learning classifier. It returns a risk score and
recommendation, and can use Groq to generate an optional plain-language
explanation. Users create an account or sign in before they can assess URLs.

> **Scope:** This project assesses submitted URL strings. It is not a network
> firewall, web application firewall (WAF), browser extension, or guarantee
> that a URL is safe.

## Features

- Account registration, password verification, and cookie-based sessions.
- URL assessment using the model files in `models/`.
- Risk score, classification, indicators, and recommendation.
- Optional Groq-generated explanation, with a classifier-based fallback if
  Groq is not configured or unavailable.
- SQLite storage for user accounts and sessions.
- Static frontend served by the Python application.

## Project layout

```text
.
├── auth_server.py        # HTTP server, authentication API, and URL analysis
├── requirements.txt      # Python dependencies (scikit-learn pinned to 1.6.1)
├── aegis_auth.sqlite3    # Created locally when the server starts
├── models/               # Required pre-trained model artifacts
└── Frontend/             # HTML, CSS, JavaScript, and static assets
```

The background video is intentionally not included in the GitHub repository.
The pages work without it.

## Requirements

- Python 3.10 or newer.
- Git, if cloning the repository.
- A Groq API key is optional. Without it, URL classification still works and
  the app displays its built-in explanation instead.

## Setup on Windows

Open PowerShell in the project directory:

```powershell
git clone https://github.com/deva424/WAF.git
cd WAF
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

If PowerShell does not allow activation, run the environment's Python directly:

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

The serialized model artifacts were created with scikit-learn 1.6.1, so
`requirements.txt` pins that version. Use the environment created above when
running the app; a different Python environment may have incompatible package
versions and produce model-loading warnings or errors.

## Configure Groq (optional)

Create a `.env` file in the project root. Do not commit this file or share its
contents:

```dotenv
GROQ_API_KEY=your_groq_api_key
GROQ_MODEL=openai/gpt-oss-20b
```

The API key is read only by the server. If the model is unavailable to your
Groq account, set `GROQ_MODEL` to an active model ID available to your key.
Restart the server after changing `.env`.

## Run locally

With `.venv` active:

```powershell
python -m auth_server
```

Or run it without activating the environment:

```powershell
.\.venv\Scripts\python.exe -m auth_server
```

Open [http://127.0.0.1:8000](http://127.0.0.1:8000). Create an account, sign in,
then open the link checker. Press `Ctrl+C` in the terminal to stop the server.

The server creates `aegis_auth.sqlite3` in the project directory on startup.
Keep this database on persistent storage if you need to preserve user accounts
between restarts.

## Deployment notes

`auth_server.py` uses Python's built-in `http.server`; it is intended for local
use and development, not as a hardened public production server. Do not expose
it directly to the internet.

For a real deployment:

1. Use a maintained production application server and a supported hosting
   platform; this project does not currently provide a production server
   configuration or deployment workflow.
2. Terminate HTTPS at a properly configured reverse proxy. If using the
   current handler behind a proxy, the proxy must overwrite
   `X-Forwarded-Proto` with the actual external scheme so secure session cookies
   and same-origin checks work correctly. Do not trust this header from
   arbitrary clients.
3. Store `GROQ_API_KEY` in the hosting provider's secret manager or protected
   environment configuration, not in source control.
4. Provide persistent, access-controlled storage for the SQLite database and
   ensure it is included in secure backups.
5. Review authentication, rate limiting, logging, session policy, and
   operational monitoring before accepting public traffic.
6. Do not expose detailed server errors or secrets in logs. Model files loaded
   with `joblib` must be treated as trusted application artifacts.

The GitHub Pages static hosting service alone cannot run this Python backend;
the frontend and API must be served by a host that can run the application.

## Troubleshooting

- **`ModuleNotFoundError` or missing packages:** activate `.venv` and run
  `python -m pip install -r requirements.txt` again.
- **scikit-learn `InconsistentVersionWarning`:** check that the server is being
  run by the project `.venv` and that it has scikit-learn 1.6.1 installed.
- **Groq errors:** URL classification can still succeed using the fallback
  explanation. Check the key, model ID, account access, and quota in GroqCloud.
- **Cannot connect to the scanner:** run `python -m auth_server` from the
  project root and use the printed local address.
- **Missing model files:** ensure the complete `models/` directory is present.

## Security and privacy

Passwords are stored as salted PBKDF2 hashes. Session tokens are stored as
hashes and sent in `HttpOnly`, `SameSite=Lax` cookies. Submitted URLs are sent
to Groq when Groq explanations are enabled; avoid submitting links containing
private tokens or other sensitive data.
