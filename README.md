# Gmail Phishing & Malicious-Link Detector

A Python-based Gmail security automation project that continuously monitors a Gmail inbox, analyzes newly received emails for phishing and malicious-link indicators, records the analysis in SQLite, and sends a security alert when an email reaches the configured risk threshold.

> **Important:** This project is a heuristic security-assistance tool. It does not guarantee that an email is malicious or legitimate. A legitimate email may be flagged, and sophisticated phishing emails may not be detected.

---

## 1. Project Overview

The detector connects to Gmail using:

- **IMAP over SSL** for reading emails
- **SMTP over SSL** for sending security alerts
- **SQLite** for storing scan and alert status
- **Python rule-based analysis** for phishing indicators
- **Optional Google Safe Browsing API** for URL reputation checks

The main goal is:

> **One phishing email = one analysis = one alert**

The system also protects itself from analyzing its own generated alert emails.

---

## 2. Main Features

- Continuously monitors a Gmail inbox.
- Processes newly received/unseen messages.
- Extracts:
  - Sender
  - Subject
  - Email body
  - URLs
  - Attachments
- Checks sender/domain indicators.
- Detects suspicious URL characteristics.
- Checks potentially dangerous attachment extensions.
- Optionally checks URLs with Google Safe Browsing.
- Assigns a risk level:
  - `LOW`
  - `MEDIUM`
  - `HIGH`
  - `CRITICAL`
- Stores scan results in SQLite.
- Prevents the same Gmail UID from being analyzed repeatedly.
- Sends one alert for a qualifying phishing/high-risk email.
- Prevents detector-generated alert emails from being analyzed again.
- Uses an `alert_sent` database field to track alert status.
- Keeps a log in `detector.log`.
- Does **not** open or click detected URLs.

---

## 3. Project Architecture

```text
                    Gmail Inbox
                         |
                         v
                 IMAP SSL Connection
                         |
                         v
                  Find New Emails
                         |
                         v
              Check Detector Alert Marker
                    /             \
                  YES              NO
                   |                |
                   v                v
                 IGNORE       Check Gmail UID
                                  |
                           Already scanned?
                            /           \
                          YES            NO
                           |              |
                           v              v
                         SKIP       Parse Email
                                         |
                                         v
                             Extract Body / URLs /
                                Attachments
                                         |
                                         v
                                Phishing Analysis
                                         |
                                         v
                               Risk Score / Level
                                         |
                              +----------+----------+
                              |                     |
                         LOW/MEDIUM*          HIGH/CRITICAL
                              |                     |
                              v                     v
                         Save Result          Save Result
                                                    |
                                                    v
                                               Send ONE Alert
                                                    |
                                                    v
                                           Mark alert_sent = 1
                                                    |
                                                    v
                                                   DONE
```

`MEDIUM` alert behavior depends on `ALERT_ON_MEDIUM`.

---

## 4. Project Structure

```text
gmail-phishing-detector/
│
├── app.py
├── config.py
├── database.py
├── detector.py
├── email_utils.py
├── notifier.py
├── requirements.txt
├── README.md
├── .gitignore
│
├── .env                 # You create this locally - DO NOT upload
├── phishing_detector.db # Created automatically - DO NOT upload
└── detector.log         # Created automatically - DO NOT upload
```

### File responsibilities

| File | Purpose |
|---|---|
| `app.py` | Main Gmail monitoring loop and processing workflow |
| `config.py` | Loads environment variables and application configuration |
| `database.py` | SQLite database creation, scan tracking and alert tracking |
| `detector.py` | Rule-based phishing/risk analysis |
| `email_utils.py` | Email parsing, body extraction, URL extraction and attachment metadata |
| `notifier.py` | Creates and sends security alert emails |
| `requirements.txt` | Python dependencies |
| `.env` | Local Gmail credentials/configuration; never commit this file |
| `phishing_detector.db` | Local scan database |
| `detector.log` | Application log |

---

# 5. Requirements

Before starting, install:

### Required

- Windows, Linux, or macOS
- Python 3.x
- A Gmail account
- Gmail 2-Step Verification
- Gmail App Password
- Internet connection

### Optional

- Google Safe Browsing API key

---

# 6. Check Python Installation

Open Command Prompt or PowerShell.

Run:

```bash
python --version
```

You should get something similar to:

```text
Python 3.x.x
```

If `python` does not work, try:

```bash
py --version
```

If Python is not installed, install Python from the official Python website.

Make sure Python is added to your system `PATH` during installation.

---

# 7. Download / Clone the Project

## Option A - Download ZIP

Download the project ZIP from GitHub and extract it.

Example:

```text
C:\Users\YourName\Downloads\gmail-phishing-detector
```

Open a terminal inside the project folder.

---

## Option B - Clone from GitHub

After creating your GitHub repository:

```bash
git clone https://github.com/UVARAJKUMAR/ai-gmail-phishing-detector.git
```

Then:

```bash
cd ai-gmail-phishing-detector
```

Replace `YOUR_USERNAME` with your GitHub username.

---

# 8. Create a Python Virtual Environment

Inside the project folder:

```bash
python -m venv .venv
```

Activate it.

### Windows CMD

```cmd
.venv\Scripts\activate
```

### Windows PowerShell

```powershell
.\.venv\Scripts\Activate.ps1
```

### Linux / macOS

```bash
source .venv/bin/activate
```

After activation, you should see something similar to:

```text
(.venv)
```

at the beginning of your terminal prompt.

---

# 9. Install Dependencies

Run:

```bash
pip install -r requirements.txt
```

The project requires:

```text
python-dotenv
requests
```

Python standard-library modules are used for Gmail IMAP/SMTP, email parsing, SQLite, logging, URL parsing, and related operations.

---

# 10. Configure Gmail

The project uses Gmail IMAP to read emails and Gmail SMTP to send security alerts.

The configured Gmail endpoints are:

```text
IMAP:
imap.gmail.com
Port: 993
SSL

SMTP:
smtp.gmail.com
Port: 465
SSL
```

---

# 11. Enable Gmail 2-Step Verification

A Gmail App Password requires 2-Step Verification to be enabled on the Google account.

Go to your Google Account security settings.

Enable:

```text
2-Step Verification
```

Then create an:

```text
App Password
```

Use the generated App Password for this project.

> Never use your normal Gmail password in `.env`.

---

# 12. Create the `.env` File

Inside the project root, create:

```text
.env
```

Example:

```env
GMAIL_ADDRESS=yourgmail@gmail.com
GMAIL_APP_PASSWORD=your_16_digit_app_password

ALERT_TO=yourgmail@gmail.com

POLL_SECONDS=60
MAX_EMAILS_PER_CYCLE=20

SAFE_BROWSING_API_KEY=

ALLOWED_DOMAINS=
BLOCKED_DOMAINS=

ALERT_ON_MEDIUM=false
```

### Configuration explanation

#### `GMAIL_ADDRESS`

The Gmail account monitored by the detector.

```env
GMAIL_ADDRESS=yourgmail@gmail.com
```

#### `GMAIL_APP_PASSWORD`

The Gmail App Password.

```env
GMAIL_APP_PASSWORD=your_app_password
```

Do not share this value.

#### `ALERT_TO`

Email address that receives security alerts.

```env
ALERT_TO=yourgmail@gmail.com
```

It can be the same Gmail account or another email address.

#### `POLL_SECONDS`

How often the program checks Gmail.

```env
POLL_SECONDS=60
```

This means the detector waits approximately 60 seconds between monitoring cycles.

#### `MAX_EMAILS_PER_CYCLE`

Maximum number of emails processed during one cycle.

```env
MAX_EMAILS_PER_CYCLE=20
```

#### `SAFE_BROWSING_API_KEY`

Optional Google Safe Browsing API key.

```env
SAFE_BROWSING_API_KEY=
```

If blank, Safe Browsing checking is disabled.

#### `ALLOWED_DOMAINS`

Optional comma-separated trusted domains.

Example:

```env
ALLOWED_DOMAINS=example.com,company.com
```

#### `BLOCKED_DOMAINS`

Optional comma-separated blocked domains.

Example:

```env
BLOCKED_DOMAINS=bad-example.com,suspicious-example.com
```

#### `ALERT_ON_MEDIUM`

Controls whether MEDIUM-risk emails generate alerts.

To alert on MEDIUM:

```env
ALERT_ON_MEDIUM=true
```

To alert only on HIGH and CRITICAL:

```env
ALERT_ON_MEDIUM=false
```

---

# 13. Protect the `.env` File

Never upload your `.env` file to GitHub.

Your `.gitignore` should contain at least:

```gitignore
.env
.venv/
__pycache__/
*.pyc
*.db
*.log
```

This prevents credentials, databases, and logs from being committed accidentally.

---

# 14. Initialize the Database

You normally do not need to create the database manually.

When the application starts:

```bash
python app.py
```

the program calls the database initialization function.

The SQLite database is:

```text
phishing_detector.db
```

The main table is:

```text
scanned_emails
```

It stores information such as:

- Gmail UID
- Message ID
- Sender
- Subject
- Risk level
- Score
- Detection reasons
- Alert status
- Scan time

---

# 15. Database Alert Tracking

The important field is:

```text
alert_sent
```

The purpose is to remember whether a security alert has already been successfully sent for an email.

Conceptually:

```text
alert_sent = 0
```

means:

```text
No successful alert recorded.
```

And:

```text
alert_sent = 1
```

means:

```text
Alert already sent.
```

This helps enforce:

```text
ONE PHISHING EMAIL
        ↓
ONE ALERT
```

---

# 16. Run the Application

Make sure the virtual environment is active.

Run:

```bash
python app.py
```

You should see the application startup information.

Example:

```text
======================================================================
GMAIL PHISHING DETECTION & SECURITY ALERT SYSTEM
======================================================================
Monitoring Gmail : yourgmail@gmail.com
Polling interval : 60 seconds
Alert rule       : ONE PHISHING EMAIL = ONE ALERT
Duplicate alerts : PROTECTED
Self-alert loop  : PROTECTED
======================================================================
Press Ctrl+C to stop.
======================================================================
```

The application will continue running.

---

# 17. How the Monitoring Works

The application continuously performs this cycle:

```text
Start
  ↓
Connect to Gmail
  ↓
Select INBOX
  ↓
Search for new/unseen messages
  ↓
Get Gmail UID
  ↓
Check database
  ↓
Already scanned?
  ├── YES → Skip
  └── NO
       ↓
   Fetch email
       ↓
   Parse email
       ↓
   Check whether it is a detector-generated alert
       ↓
   Extract body, URLs and attachments
       ↓
   Analyze email
       ↓
   Calculate score
       ↓
   Assign risk
       ↓
   Save result
       ↓
   Alert if required
       ↓
   Wait
       ↓
   Repeat
```

---

# 18. Risk Levels

The current detector uses these thresholds:

| Score | Risk |
|---:|---|
| `0–19` | LOW |
| `20–39` | MEDIUM |
| `40–69` | HIGH |
| `70+` | CRITICAL |

These values are based on the current rule-based detector.

---

# 19. What Does the Detector Check?

## Sender

The detector checks indicators such as:

- Missing/malformed sender address
- Display-name/domain mismatch
- Blocked sender domain
- Allowed sender domain

---

## URLs

The detector checks indicators such as:

- Raw IP addresses
- Punycode
- URL shorteners
- `@` characters
- Non-HTTPS URLs
- Unusual ports
- Invalid ports
- Very long URLs
- Many subdomain levels
- Security/credential-related keywords
- Blocked domains

---

## Email Content

The detector looks for multiple urgency/security-related keywords.

Examples include:

```text
verify
urgent
immediately
suspended
locked
password
login
confirm
security alert
invoice
payment
refund
gift card
account
```

---

## Attachments

The detector checks filenames for potentially dangerous extensions.

Examples include:

```text
.exe
.scr
.js
.vbs
.bat
.cmd
.ps1
.msi
.jar
.lnk
.iso
.img
.reg
```

The detector records attachment metadata but does not execute the attachment.

---

# 20. Google Safe Browsing

The project has optional support for Google Safe Browsing.

If:

```env
SAFE_BROWSING_API_KEY=
```

is empty, Safe Browsing checking is disabled.

If an API key is configured, the detector can query URLs for known threat matches.

The current detector does not open the suspicious URL in a browser.

---

# 21. Important Security Behavior

The detector does **not** click suspicious links.

It extracts and analyzes URL strings.

Conceptually:

```text
Email
  ↓
Extract URL
  ↓
Analyze URL string
  ↓
Risk score
```

Not:

```text
Email
  ↓
Open URL
  ↓
Visit website
```

This is important because automatically opening an unknown phishing URL would create unnecessary security risk.

---

# 22. One Phishing Email = One Alert

This is one of the main design rules of the project.

Example:

```text
Email UID 12345
       ↓
Analyze
       ↓
CRITICAL
       ↓
Save result
       ↓
Send ONE alert
       ↓
alert_sent = 1
```

If the same UID appears again:

```text
UID 12345
   ↓
Already scanned
   ↓
SKIP
```

No second analysis.

No second alert.

---

# 23. Detector Alert Protection

When the detector sends an alert email, that alert can arrive in the monitored Gmail inbox.

Without protection:

```text
Phishing email
      ↓
Detector
      ↓
Alert email
      ↓
Detector analyzes alert
      ↓
Another alert
      ↓
Loop
```

The updated project prevents this behavior using a dedicated detector-alert marker.

The generated alert contains a marker that allows the detector to recognize:

```text
This email was generated by the detector.
```

The detector then ignores it instead of running the phishing analysis again.

---

# 24. Alert Email

When a qualifying email is detected, the notifier sends a security alert.

The alert contains information such as:

```text
Risk Level
Risk Score
Original Sender
Sender Domain
Original Subject
Detection Reasons
Suspicious URLs
Attachment Information
Recommended Action
Security Notice
```

The alert is intended to help the recipient understand why the original email was flagged.

---

# 25. Testing the Project

## Test 1 - Normal Email

Send yourself a normal email.

Expected behavior:

```text
Email received
     ↓
Analyzed
     ↓
LOW / MEDIUM
     ↓
Saved to database
     ↓
No alert (if MEDIUM alerts are disabled)
```

---

## Test 2 - Suspicious Email

For testing, use a harmless test message containing several phishing-like indicators.

Do not use a real malicious attachment or real malicious website.

Expected behavior:

```text
Test email
    ↓
Analyzer
    ↓
HIGH / CRITICAL
    ↓
Database record
    ↓
ONE security alert
```

---

## Test 3 - Detector Alert

After a security alert is generated:

```text
Security alert arrives
       ↓
Detector sees generated-alert marker
       ↓
Detector ignores it
       ↓
No new alert
```

---

## Test 4 - Duplicate Processing

If the same Gmail UID is encountered again:

```text
UID already exists in database
       ↓
Skip processing
```

There should not be another analysis or alert for that UID.

---

# 26. View the Logs

The application writes logs to:

```text
detector.log
```

You can open it with a text editor.

Example entries can show:

```text
Processing UID=12345
Risk=HIGH
Score=65
Sending security alert
SUCCESS: exactly ONE alert sent
```

The log is useful when troubleshooting Gmail connections, analysis, or alert delivery.

---

# 27. Stop the Detector

In the terminal where the program is running:

```text
Ctrl + C
```

The detector will stop.

---

# 28. Start It Again

Activate the virtual environment if necessary:

```cmd
.venv\Scripts\activate
```

Then:

```bash
python app.py
```

The SQLite database keeps the previous scan records.

---

# 29. Troubleshooting

## Problem: `python` is not recognized

Try:

```cmd
py --version
```

If that works, use:

```cmd
py app.py
```

---

## Problem: `pip` is not recognized

Use:

```cmd
python -m pip install -r requirements.txt
```

---

## Problem: Missing environment variable

Example:

```text
Missing required environment variable: GMAIL_ADDRESS
```

Check that `.env` exists in the project root and contains:

```env
GMAIL_ADDRESS=yourgmail@gmail.com
GMAIL_APP_PASSWORD=your_app_password
```

---

## Problem: Gmail authentication fails

Check:

1. Gmail address is correct.
2. 2-Step Verification is enabled.
3. App Password is correct.
4. The App Password has not been revoked.
5. You are not using your normal Gmail password.
6. `.env` is being loaded from the project directory.

---

## Problem: SMTP alert is not being sent

Check:

```text
GMAIL_ADDRESS
GMAIL_APP_PASSWORD
ALERT_TO
```

Also inspect:

```text
detector.log
```

The notifier uses:

```text
smtp.gmail.com
Port 465
SSL
```

---

## Problem: Old database schema error

If an older database was created before `alert_sent` existed, the updated project includes database initialization/migration handling for the `alert_sent` field.

If you want a completely clean development test, stop the application and back up/remove:

```text
phishing_detector.db
```

Then run:

```bash
python app.py
```

A fresh database will be created.

> Do not delete the database if you need to preserve previous scan history.

---

## Problem: Too many false positives

This project currently uses heuristic/rule-based detection.

That means legitimate emails can sometimes receive high scores.

For example, legitimate emails containing words such as:

```text
login
security
verify
account
password
urgent
```

may contribute to the risk score.

The project should therefore be treated as a security-assistance system rather than a perfect phishing classifier.

---

# 30. Security Rules for GitHub

Before pushing the project to GitHub, verify that these files are NOT committed:

```text
.env
phishing_detector.db
detector.log
*.db
*.log
.venv/
__pycache__/
```

Most importantly:

```text
.env
```

must never contain credentials in GitHub.

If a Gmail App Password has ever been accidentally uploaded or shared, revoke it and create a new one.

---

# 31. GitHub Repository Setup

Recommended repository name:

```text
ai-gmail-phishing-detector
```

Recommended description:

```text
Automated Gmail phishing and malicious-link detection system using Python, rule-based risk analysis, SQLite, IMAP, and SMTP.
```

---

# 32. Initialize Git

Open a terminal inside the project folder.

Run:

```bash
git init
```

Check the files:

```bash
git status
```

You should verify that `.env`, databases, logs, and the virtual environment are ignored.

---

# 33. Add the Project to Git

Run:

```bash
git add .
```

Then check:

```bash
git status
```

Before continuing, make sure you do **not** see:

```text
.env
phishing_detector.db
detector.log
.venv/
```

If they appear, stop and fix `.gitignore`.

---

# 34. Create the First Commit

Run:

```bash
git commit -m "Initial commit - Gmail phishing detector"
```

---

# 35. Connect GitHub Repository

Create a GitHub repository named:

```text
ai-gmail-phishing-detector
```

Then GitHub will provide commands similar to:

```bash
git branch -M main
git remote add origin https://github.com/YOUR_USERNAME/ai-gmail-phishing-detector.git
git push -u origin main
```

Replace:

```text
YOUR_USERNAME
```

with your GitHub username.

---

# 36. Verify GitHub

Open your GitHub repository in the browser.

You should see files such as:

```text
app.py
config.py
database.py
detector.py
email_utils.py
notifier.py
requirements.txt
README.md
.gitignore
```

You should **not** see:

```text
.env
*.db
*.log
.venv
```

---

# 37. Recommended GitHub Project Description

You can use:

> A Python-based Gmail phishing and malicious-link detection system that monitors incoming emails, analyzes sender information, URLs, email content, and attachments using rule-based security heuristics, stores results in SQLite, and sends automated security alerts with duplicate and self-alert protection.

---

# 38. Current Limitations

The current detector is intentionally a rule-based system.

It does not guarantee detection of every phishing email.

Current limitations include:

- Rule-based detection can create false positives.
- Sophisticated phishing emails can bypass simple heuristics.
- Sender reputation is limited.
- SPF/DKIM/DMARC analysis is not currently part of the detector.
- Domain age/reputation analysis is not currently implemented.
- Attachment contents are not deeply analyzed.
- No machine-learning classifier is currently integrated.
- No dashboard is currently included.
- Gmail is the current email provider integration.
- Alert delivery depends on SMTP connectivity and authentication.

---

# 39. Future Improvements

Possible future versions can add:

### Email Authentication

- SPF analysis
- DKIM analysis
- DMARC analysis
- Reply-To mismatch detection

### Domain Intelligence

- Domain reputation
- Domain age
- Look-alike domain detection
- Brand impersonation detection

### Machine Learning

A future architecture could combine:

```text
Rule-Based Detection
        +
Machine Learning Model
        +
URL Reputation
        +
Email Authentication
        ↓
   Final Risk Score
```

### AI / NLP

Possible future additions:

- Transformer-based phishing classification
- NLP-based email classification
- LLM-assisted explanation of detection reasons
- RAG-based security knowledge lookup

### Automation

Possible future integrations:

- ServiceNow incident creation
- Microsoft Teams notification
- Security dashboard
- Automated ticket creation
- SOC workflow integration
- Analyst feedback loop

---

# 40. Recommended Production Architecture

For a more advanced version:

```text
                         Gmail
                           |
                           v
                    Email Collector
                           |
                           v
                    Email Parser
                           |
          +----------------+----------------+
          |                |                |
          v                v                v
       Sender            URLs          Attachments
       Analysis         Analysis         Analysis
          |                |                |
          +----------------+----------------+
                           |
                           v
                    Rule-Based Engine
                           |
                           v
                    ML / AI Classifier
                           |
                           v
                    Risk Engine
                           |
             +-------------+-------------+
             |                           |
             v                           v
          Database                  Alert Engine
                                         |
                              +----------+----------+
                              |                     |
                              v                     v
                          Email Alert          ServiceNow /
                                              Teams / SOC
```

---

# 41. Disclaimer

This project is intended for educational, defensive, and security-automation purposes.

The detector provides a heuristic assessment and should not be treated as a definitive security verdict.

For important security decisions, verify suspicious messages through trusted channels and follow your organization's security procedures.

---

# 42. Quick Start

For experienced users, the complete setup is:

```bash
git clone https://github.com/YOUR_USERNAME/ai-gmail-phishing-detector.git

cd ai-gmail-phishing-detector

python -m venv .venv
```

Windows:

```cmd
.venv\Scripts\activate
```

Install:

```bash
pip install -r requirements.txt
```

Create `.env`:

```env
GMAIL_ADDRESS=yourgmail@gmail.com
GMAIL_APP_PASSWORD=your_app_password
ALERT_TO=yourgmail@gmail.com
POLL_SECONDS=60
MAX_EMAILS_PER_CYCLE=20
SAFE_BROWSING_API_KEY=
ALLOWED_DOMAINS=
BLOCKED_DOMAINS=
ALERT_ON_MEDIUM=false
```

Run:

```bash
python app.py
```

Stop:

```text
Ctrl + C
```

---

## 43. Project Goal

The goal of this project is to demonstrate how Python can be used to automate a practical security workflow:

```text
Receive Email
      ↓
Automatically Analyze
      ↓
Calculate Risk
      ↓
Record Result
      ↓
Alert Security/User
      ↓
Prevent Duplicate Alerts
      ↓
Continue Monitoring
```

This makes the project more than a simple phishing classifier: it demonstrates an end-to-end **email security automation workflow**.
