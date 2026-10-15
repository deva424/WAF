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

## Deploy to Render

The application can run as a Render Web Service. It reads Render's `PORT`
environment variable, accepts an `AEGIS_HOST` setting, and supports a
configurable database path through `AEGIS_DB_PATH`.

1. Push the project to GitHub and sign in to the [Render Dashboard](https://dashboard.render.com/).
2. Select **New → Web Service**, connect GitHub, and choose this repository and
   the `main` branch.
3. Set the service's root directory to the repository root and choose the
   **Python** runtime.
4. Use these commands:

   ```text
   Build: pip install -r requirements.txt
   Start: python -m auth_server
   ```

5. Add these environment variables under the service's **Environment** settings:

   | Name | Value |
   | --- | --- |
   | `PYTHON_VERSION` | `3.12.8` |
   | `AEGIS_HOST` | `0.0.0.0` |
   | `GROQ_API_KEY` | Your Groq API key (optional) |
   | `GROQ_MODEL` | `openai/gpt-oss-20b` |

   Render sets `PORT` automatically; the server uses it in preference to
   `AEGIS_PORT`. Do not add the API key to GitHub or frontend code.

6. Click **Create Web Service**, wait for the first deployment to finish, and
   open the `onrender.com` URL. Test registration, sign-in, and URL assessment.
   Render can deploy later changes automatically when they are pushed to the
   connected branch.

### Persisting accounts on Render

The default SQLite database lives beside the application code. Render's
filesystem is ephemeral unless a persistent disk is attached, so accounts
stored at the default path may be lost during restarts or redeployments.

For persistent accounts, attach a Render disk to the web service with mount
path `/var/data`, then add this service environment variable:

```text
AEGIS_DB_PATH=/var/data/aegis_auth.sqlite3
```

The application creates the database directory if it does not exist. Render
persistent disks require a paid web service plan. Without a disk, use the
deployment only for a temporary demo and expect locally stored accounts to be
lost.

Render terminates HTTPS before proxying requests to the service. The app uses
`X-Forwarded-Proto` to set secure session cookies and validate request origins;
do not run this server directly on the public internet outside a trusted,
correctly configured hosting proxy.

This project currently uses Python's built-in `http.server`, which is suitable
for a small demo but is not a hardened production application server. Before
handling real users, review the authentication and session design, add
appropriate rate limiting and monitoring, and consider migrating to a
production web framework and database.

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
