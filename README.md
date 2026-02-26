# iMAP-Sync-Manager---Python
Desktop IMAP email sync tool with a modern PyQt6 GUI. Syncs folders between two IMAP accounts (copy + delete) using Message-ID matching, newest-to-oldest, with queueing, logging, and safe credential testing.


# IMAP Sync Manager

IMAP Sync Manager is a Python desktop application for Windows (and other platforms with Qt) that lets you safely **synchronize emails between two IMAP accounts**.

It provides a modern PyQt6 GUI to:

- Configure multiple IMAP accounts.
- Define "from → to" sync setups.
- Compare messages by headers (Message-ID / Subject / Date / Size) instead of UIDs.
- Copy messages that are missing on the target.
- Optionally delete messages on the target that no longer exist on the source (mirror mode).
- Process messages **newest to oldest**.
- Run multiple sync setups in a queue.
- View live progress and logs.

> Note: This tool is intended for admins/power users who understand the risks of deleting emails on the target server. Test carefully on non-critical accounts first.

---

## Features

### Accounts

- Add, edit, and delete IMAP accounts.
- Stores:
  - Account name
  - IMAP server
  - Port
  - Email address
  - Password (stored locally in SQLite as plain text – use only on trusted machines)
  - SSL/TLS on/off
- **Connection test** runs automatically when you save an account:
  - On success: shows a confirmation.
  - On failure: shows the error and lets you decide if you still want to save the account.

### Sync Setups

Each sync setup defines:

- A **From** account (source).
- A **To** account (target).
- Folders:
  - Either all folders from the source.
  - Or a comma-separated list (e.g. `INBOX,Sent,Archive`).
- Active flag (can disable a setup without deleting it).

A sync setup will:

1. For each folder:
   - Build a map of messages on **From** via:
     - `Message-ID`, or
     - fallback `(Subject, Date, Size)` if `Message-ID` is missing.
   - Build the same map on **To**.
2. Compare keys:
   - In source but not in target → **copy** to target.
   - In target but not in source → **delete** from target.
3. Copy messages in **newest-to-oldest** order (by source UID).
4. Preserve:
   - Original flags.
   - INTERNALDATE (timestamp).
   - Raw content (headers, body, attachments).

A local SQLite DB (`imap_syncer.db`) is used to:

- Store accounts.
- Store sync setups.
- Keep a history of copied messages (for reference/logging).

> Important: The “truth” is always the **From** account. The target will be mirrored to match it.

### Queue & Progress

- You can queue multiple sync setups.
- Only one sync job runs at a time.
- The **Status / Logs** tab shows:
  - Current job description.
  - Progress bar (% based on copy + delete operations).
  - Live log output (per-folder analysis, operations, errors).

### Error Handling

- Network, DNS, login, and SSL errors are logged and shown in modal dialogs.
- For EOF / connection drop errors, hints are shown:
  - Check hostname is IMAP, not POP/webmail.
  - Check port/SSL combination.
  - Check whether IMAP is enabled on the server.
- A log file `imap_syncer.log` is written next to the script.
- Logs can be exported via “Save log to file…” in the UI.

---

## Requirements

- Python 3.11+ (tested with 3.12)
- Qt-compatible desktop environment (Windows is the primary target)

Python packages:

- `PyQt6`
- `IMAPClient`

Example `requirements.txt`:
PyQt6
IMAPClient

## Running the App

### Clone the repository

git clone https://github.com/CreareGuru/iMAP-Sync-Manager---Python.git

iMAP-Sync-Manager---Python

### Create a virtual environment (recommended)

python -m venv venv
# Windows:
venv\\Scripts\\activate
# Linux/macOS:
source venv/bin/activate

### Install dependencies

pip install -r requirements.txt

### Run the app

python imap_sync_app.py

A modern dark-themed window called “IMAP Sync Manager” should open.

---

## Usage

### 1. Configure Accounts

Open the Accounts tab.
Click “Add account”.
Fill in:
- Account name (label)
- IMAP server (e.g. imap.example.com)
- Port (typically 993 for SSL, 143 for plain)
- Email address
- Password
- Check “Use SSL/TLS”
Click Save.
If the test fails, you can still save the account.

### 2. Create Sync Setups

Open Sync setups.
Click “Add sync setup”.
Enter:
- Setup name
- From account
- To account
- Active
- Folders (all or custom list)
Save.

### 3. Run Syncs

Select a setup.
Click “Start selected”.
Watch progress in Status / Logs.
Stop sync if needed.

### 4. Logs

Logs appear in Status / Logs.
A file imap_syncer.log is created.
Logs can be saved to file.

---

## Data & Storage

SQLite database:
imap_syncer.db

Tables:
- accounts
- sync_setups
- synced_messages

Passwords stored in plain text. Use only on secure systems.

---

## Safety Notes

This app can delete emails on the target server.
Test on non-critical mailboxes first.
Always keep backups.

---

## Project Structure

imap-sync-manager/

├─ imap_sync_app.py

├─ requirements.txt

├─ README.md

└─ imap_syncer.db

---

## License

MIT License – see LICENSE.
"""
