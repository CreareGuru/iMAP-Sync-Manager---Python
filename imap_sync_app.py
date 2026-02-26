import sys
import os
import json
import sqlite3
import traceback
import socket
from datetime import datetime
from typing import List, Dict, Optional, Tuple

from email import message_from_bytes
from imapclient import IMAPClient

from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QPalette, QColor, QFont
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QTabWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QTableWidget, QTableWidgetItem, QDialog, QFormLayout,
    QLineEdit, QSpinBox, QCheckBox, QLabel, QMessageBox, QComboBox,
    QProgressBar, QPlainTextEdit, QFileDialog, QHeaderView, QStyleFactory, QStatusBar
)


# =============================================================================
# Database layer
# =============================================================================

class DatabaseManager:
    """
    Simple SQLite-based storage for:
      - Accounts
      - Sync setups
      - Synced messages (history)
    """

    def __init__(self, db_path: str = "imap_syncer.db"):
        self.db_path = db_path
        self._init_db()

    def _connect(self):
        # New connection per call (safe across threads)
        return sqlite3.connect(self.db_path, check_same_thread=False)

    def _init_db(self):
        with self._connect() as conn:
            c = conn.cursor()
            c.execute("""
                CREATE TABLE IF NOT EXISTS accounts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    server TEXT NOT NULL,
                    port INTEGER NOT NULL,
                    email TEXT NOT NULL,
                    password TEXT NOT NULL,
                    use_ssl INTEGER NOT NULL DEFAULT 1
                )
            """)
            c.execute("""
                CREATE TABLE IF NOT EXISTS sync_setups (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    from_account_id INTEGER NOT NULL,
                    to_account_id INTEGER NOT NULL,
                    folders TEXT,              -- JSON: list of folder names or NULL for all
                    active INTEGER NOT NULL DEFAULT 1,
                    last_run TEXT
                )
            """)
            c.execute("""
                CREATE TABLE IF NOT EXISTS synced_messages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    sync_setup_id INTEGER NOT NULL,
                    folder TEXT NOT NULL,
                    from_uid INTEGER NOT NULL,
                    to_uid INTEGER,
                    synced_at TEXT NOT NULL
                )
            """)
            conn.commit()

    # ---------------- Accounts ----------------

    def get_accounts(self) -> List[Dict]:
        with self._connect() as conn:
            c = conn.cursor()
            c.execute("SELECT id, name, server, port, email, password, use_ssl FROM accounts")
            rows = c.fetchall()
        accounts = []
        for r in rows:
            accounts.append({
                "id": r[0],
                "name": r[1],
                "server": r[2],
                "port": r[3],
                "email": r[4],
                "password": r[5],
                "use_ssl": bool(r[6]),
            })
        return accounts

    def get_account(self, account_id: int) -> Optional[Dict]:
        with self._connect() as conn:
            c = conn.cursor()
            c.execute(
                "SELECT id, name, server, port, email, password, use_ssl "
                "FROM accounts WHERE id = ?",
                (account_id,)
            )
            r = c.fetchone()
        if not r:
            return None
        return {
            "id": r[0],
            "name": r[1],
            "server": r[2],
            "port": r[3],
            "email": r[4],
            "password": r[5],
            "use_ssl": bool(r[6]),
        }

    def add_account(self, name: str, server: str, port: int,
                    email: str, password: str, use_ssl: bool):
        with self._connect() as conn:
            c = conn.cursor()
            c.execute("""
                INSERT INTO accounts (name, server, port, email, password, use_ssl)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (name, server, port, email, password, int(use_ssl)))
            conn.commit()

    def update_account(self, account_id: int, name: str, server: str, port: int,
                       email: str, password: str, use_ssl: bool):
        with self._connect() as conn:
            c = conn.cursor()
            c.execute("""
                UPDATE accounts
                SET name = ?, server = ?, port = ?, email = ?, password = ?, use_ssl = ?
                WHERE id = ?
            """, (name, server, port, email, password, int(use_ssl), account_id))
            conn.commit()

    def delete_account(self, account_id: int):
        with self._connect() as conn:
            c = conn.cursor()
            c.execute("DELETE FROM accounts WHERE id = ?", (account_id,))
            conn.commit()

    # ---------------- Sync setups ----------------

    def get_sync_setups(self) -> List[Dict]:
        with self._connect() as conn:
            c = conn.cursor()
            c.execute("""
                SELECT id, name, from_account_id, to_account_id, folders, active, last_run
                FROM sync_setups
            """)
            rows = c.fetchall()
        setups = []
        for r in rows:
            setups.append({
                "id": r[0],
                "name": r[1],
                "from_account_id": r[2],
                "to_account_id": r[3],
                "folders": json.loads(r[4]) if r[4] else None,
                "active": bool(r[5]),
                "last_run": r[6],
            })
        return setups

    def get_sync_setup(self, setup_id: int) -> Optional[Dict]:
        with self._connect() as conn:
            c = conn.cursor()
            c.execute("""
                SELECT id, name, from_account_id, to_account_id, folders, active, last_run
                FROM sync_setups
                WHERE id = ?
            """, (setup_id,))
            r = c.fetchone()
        if not r:
            return None
        return {
            "id": r[0],
            "name": r[1],
            "from_account_id": r[2],
            "to_account_id": r[3],
            "folders": json.loads(r[4]) if r[4] else None,
            "active": bool(r[5]),
            "last_run": r[6],
        }

    def add_sync_setup(self, name: str, from_account_id: int,
                       to_account_id: int, folders: Optional[List[str]],
                       active: bool = True):
        folders_json = json.dumps(folders) if folders else None
        with self._connect() as conn:
            c = conn.cursor()
            c.execute("""
                INSERT INTO sync_setups (name, from_account_id, to_account_id, folders, active, last_run)
                VALUES (?, ?, ?, ?, ?, NULL)
            """, (name, from_account_id, to_account_id, folders_json, int(active)))
            conn.commit()

    def update_sync_setup(self, setup_id: int, name: str, from_account_id: int,
                          to_account_id: int, folders: Optional[List[str]],
                          active: bool):
        folders_json = json.dumps(folders) if folders else None
        with self._connect() as conn:
            c = conn.cursor()
            c.execute("""
                UPDATE sync_setups
                SET name = ?, from_account_id = ?, to_account_id = ?, folders = ?, active = ?
                WHERE id = ?
            """, (name, from_account_id, to_account_id, folders_json, int(active), setup_id))
            conn.commit()

    def delete_sync_setup(self, setup_id: int):
        with self._connect() as conn:
            c = conn.cursor()
            c.execute("DELETE FROM sync_setups WHERE id = ?", (setup_id,))
            c.execute("DELETE FROM synced_messages WHERE sync_setup_id = ?", (setup_id,))
            conn.commit()

    def mark_sync_completed(self, setup_id: int):
        now = datetime.utcnow().isoformat(timespec="seconds") + "Z"
        with self._connect() as conn:
            c = conn.cursor()
            c.execute("UPDATE sync_setups SET last_run = ? WHERE id = ?", (now, setup_id))
            conn.commit()

    # ---------------- Synced messages (history) ----------------

    def get_synced_uids(self, setup_id: int, folder: str) -> set:
        with self._connect() as conn:
            c = conn.cursor()
            c.execute("""
                SELECT from_uid FROM synced_messages
                WHERE sync_setup_id = ? AND folder = ?
            """, (setup_id, folder))
            rows = c.fetchall()
        return {r[0] for r in rows}

    def add_synced_message(self, setup_id: int, folder: str,
                           from_uid: int, to_uid: Optional[int]):
        with self._connect() as conn:
            c = conn.cursor()
            c.execute("""
                INSERT INTO synced_messages (sync_setup_id, folder, from_uid, to_uid, synced_at)
                VALUES (?, ?, ?, ?, ?)
            """, (setup_id, folder, int(from_uid),
                  int(to_uid) if to_uid is not None else None,
                  datetime.utcnow().isoformat(timespec="seconds") + "Z"))
            conn.commit()


# =============================================================================
# Sync worker (runs in a background thread)
# =============================================================================

class SyncWorker(QThread):
    progress = pyqtSignal(int, int, str)     # current, total, status text
    status = pyqtSignal(str)                # log/status messages
    error = pyqtSignal(int, str)            # setup_id, error message
    finished = pyqtSignal(int)              # setup_id

    def __init__(self, db_path: str, setup_id: int, parent=None):
        super().__init__(parent)
        self.db_path = db_path
        self.setup_id = setup_id
        self._stop_requested = False

    def request_stop(self):
        self._stop_requested = True

    def _chunked(self, seq, size):
        for i in range(0, len(seq), size):
            yield seq[i:i+size]

    def _build_message_key_map(self, client: IMAPClient, uids: List[int]) -> Dict[Tuple, int]:
        """
        Build a map: message_key -> UID for given UIDs on a client.

        message_key is:
          ("MID", Message-ID) if present
          otherwise ("FALLBACK", Subject, Date, Size)

        This lets us match messages between servers even when UIDs differ.
        """
        key_map: Dict[Tuple, int] = {}
        if not uids:
            return key_map

        for chunk in self._chunked(uids, 100):
            data = client.fetch(
                chunk,
                [b"RFC822.HEADER", b"RFC822.SIZE"]
            )
            for uid, msg_data in data.items():
                header_bytes = msg_data.get(b"RFC822.HEADER")
                size = msg_data.get(b"RFC822.SIZE")
                if not header_bytes:
                    key = ("UIDONLY", int(uid))
                    key_map[key] = int(uid)
                    continue

                msg = message_from_bytes(header_bytes)
                msgid = msg.get("Message-ID")
                if msgid:
                    key = ("MID", msgid.strip())
                else:
                    subject = (msg.get("Subject") or "").strip()
                    date = (msg.get("Date") or "").strip()
                    key = ("FALLBACK", subject, date, size)

                key_map[key] = int(uid)

        return key_map

    def run(self):
        db = DatabaseManager(self.db_path)
        setup = db.get_sync_setup(self.setup_id)
        if not setup:
            self.error.emit(self.setup_id, "Sync setup not found.")
            return

        from_acc = db.get_account(setup["from_account_id"])
        to_acc = db.get_account(setup["to_account_id"])
        if not from_acc or not to_acc:
            self.error.emit(self.setup_id, "From/To account not found.")
            return

        self.status.emit(f"Starting sync '{setup['name']}'")

        from_client = None
        to_client = None

        try:
            # Connect to FROM
            self.status.emit(f"Connecting to FROM: {from_acc['server']}:{from_acc['port']}")
            from_client = IMAPClient(from_acc["server"],
                                     port=from_acc["port"],
                                     ssl=from_acc["use_ssl"])
            from_client.login(from_acc["email"], from_acc["password"])

            # Connect to TO
            self.status.emit(f"Connecting to TO: {to_acc['server']}:{to_acc['port']}")
            to_client = IMAPClient(to_acc["server"],
                                   port=to_acc["port"],
                                   ssl=to_acc["use_ssl"])
            to_client.login(to_acc["email"], to_acc["password"])

            # Determine folders to process
            if setup["folders"]:
                folders = setup["folders"]
            else:
                self.status.emit("Fetching folder list from source account...")
                folders = []
                for flags, delim, folder_name in from_client.list_folders():
                    if isinstance(folder_name, bytes):
                        folder_name = folder_name.decode()
                    folders.append(folder_name)

            # First pass: per-folder analysis (what to copy, what to delete)
            folder_actions: Dict[str, Dict[str, List[int]]] = {}
            total_to_copy = 0
            total_to_delete = 0

            for folder in folders:
                if self._stop_requested:
                    self.status.emit("Sync cancelled before analysis.")
                    self.finished.emit(self.setup_id)
                    return

                self.status.emit(f"Analyzing folder '{folder}'...")

                # Select/create folder on TO
                try:
                    to_client.select_folder(folder, readonly=False)
                except Exception:
                    try:
                        to_client.create_folder(folder)
                        to_client.select_folder(folder, readonly=False)
                    except Exception as e:
                        self.status.emit(
                            f"Skipping folder '{folder}' (cannot create/select on target): {e}"
                        )
                        continue

                # Select folder on FROM
                try:
                    from_client.select_folder(folder, readonly=True)
                except Exception as e:
                    self.status.emit(
                        f"Skipping folder '{folder}' (cannot select on source): {e}"
                    )
                    continue

                # Get UIDs on both sides
                from_uids = from_client.search("ALL")
                to_uids = to_client.search("ALL")

                # Build maps message_key -> UID for both sides
                from_keys = self._build_message_key_map(from_client, from_uids)
                to_keys = self._build_message_key_map(to_client, to_uids)

                from_key_set = set(from_keys.keys())
                to_key_set = set(to_keys.keys())

                # Messages that exist on FROM but not on TO -> need to copy
                keys_to_copy = from_key_set - to_key_set
                # Messages that exist on TO but not on FROM -> need to delete
                keys_to_delete = to_key_set - from_key_set

                uids_to_copy = [from_keys[k] for k in keys_to_copy]
                uids_to_delete = [to_keys[k] for k in keys_to_delete]

                # Newest to oldest for copies
                uids_to_copy = sorted(uids_to_copy, reverse=True)

                folder_actions[folder] = {
                    "copy": uids_to_copy,
                    "delete": uids_to_delete,
                }

                total_to_copy += len(uids_to_copy)
                total_to_delete += len(uids_to_delete)

                self.status.emit(
                    f"Folder '{folder}': {len(uids_to_copy)} to copy, "
                    f"{len(uids_to_delete)} to delete."
                )

            if total_to_copy == 0 and total_to_delete == 0:
                self.status.emit("Folders are already in sync. Nothing to do.")
                db.mark_sync_completed(self.setup_id)
                self.finished.emit(self.setup_id)
                return

            total_ops = total_to_copy + total_to_delete
            current = 0
            self.progress.emit(current, total_ops, "Starting sync (copy/delete)...")

            # Second pass: perform copies and deletions
            for folder, actions in folder_actions.items():
                if self._stop_requested:
                    self.status.emit("Sync cancelled by user.")
                    self.finished.emit(self.setup_id)
                    return

                copy_uids = actions["copy"]
                delete_uids = actions["delete"]

                if not copy_uids and not delete_uids:
                    continue

                self.status.emit(
                    f"Processing folder '{folder}' "
                    f"({len(copy_uids)} copies, {len(delete_uids)} deletions)..."
                )

                # Ensure folders selected again
                try:
                    from_client.select_folder(folder, readonly=True)
                except Exception as e:
                    self.status.emit(
                        f"Skipping folder '{folder}' during copy "
                        f"(cannot select source): {e}"
                    )
                    continue

                try:
                    to_client.select_folder(folder, readonly=False)
                except Exception as e:
                    self.status.emit(
                        f"Skipping folder '{folder}' during copy "
                        f"(cannot select target): {e}"
                    )
                    continue

                # 1) Copy missing messages FROM -> TO (newest to oldest)
                for chunk in self._chunked(copy_uids, 20):
                    if self._stop_requested:
                        self.status.emit("Sync cancelled by user.")
                        self.finished.emit(self.setup_id)
                        return

                    messages = from_client.fetch(chunk, ["RFC822", "FLAGS", "INTERNALDATE"])
                    for uid, msg_data in messages.items():
                        if self._stop_requested:
                            self.status.emit("Sync cancelled by user.")
                            self.finished.emit(self.setup_id)
                            return

                        raw_msg = msg_data[b"RFC822"]
                        flags = msg_data.get(b"FLAGS", ())
                        msg_time = msg_data.get(b"INTERNALDATE")

                        try:
                            _new_uid = to_client.append(
                                folder, raw_msg, flags=flags, msg_time=msg_time
                            )
                        except Exception as e:
                            self.status.emit(
                                f"Error appending message UID {uid} "
                                f"in folder '{folder}': {e}"
                            )
                            continue

                        db.add_synced_message(self.setup_id, folder, int(uid), None)
                        current += 1
                        self.progress.emit(
                            current,
                            total_ops,
                            f"Folder '{folder}': operation {current}/{total_ops} (copy)"
                        )

                # 2) Delete messages that should not be on TO
                if delete_uids:
                    for chunk in self._chunked(delete_uids, 50):
                        if self._stop_requested:
                            self.status.emit("Sync cancelled by user.")
                            self.finished.emit(self.setup_id)
                            return
                        try:
                            # No 'expunge' kwarg; expunge separately
                            to_client.delete_messages(chunk)
                            current += len(chunk)
                            self.progress.emit(
                                current,
                                total_ops,
                                f"Folder '{folder}': operation {current}/{total_ops} (delete)"
                            )
                        except Exception as e:
                            self.status.emit(
                                f"Error deleting messages in folder '{folder}': {e}"
                            )

                    try:
                        to_client.expunge()
                    except Exception as e:
                        self.status.emit(
                            f"Error expunging deletions in folder '{folder}': {e}"
                        )

            db.mark_sync_completed(self.setup_id)
            self.status.emit(f"Sync '{setup['name']}' completed successfully.")
            self.finished.emit(self.setup_id)

        except Exception as e:
            tb = traceback.format_exc()
            hint = ""
            msg = str(e)
            if "socket error: EOF" in msg:
                hint = (
                    "\n\nHint: 'socket error: EOF' often means the IMAP server "
                    "closed the connection immediately. Check that:\n"
                    "- The IMAP server host is correct (IMAP, not POP or webmail)\n"
                    "- The port matches the SSL setting (e.g. 993 with SSL, 143 without)\n"
                    "- The IMAP service is enabled on the server\n"
                )
            self.error.emit(self.setup_id, f"Error during sync: {e}{hint}\n{tb}")
        finally:
            try:
                if from_client:
                    from_client.logout()
            except Exception:
                pass
            try:
                if to_client:
                    to_client.logout()
            except Exception:
                pass


# =============================================================================
# Dialogs
# =============================================================================

class AccountDialog(QDialog):
    def __init__(self, parent=None, initial: Optional[Dict] = None):
        super().__init__(parent)
        self.setWindowTitle("IMAP Account")
        self.resize(420, 230)

        layout = QFormLayout(self)
        layout.setLabelAlignment(Qt.AlignmentFlag.AlignRight)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(12)

        self.name_edit = QLineEdit()
        self.server_edit = QLineEdit()
        self.port_spin = QSpinBox()
        self.port_spin.setRange(1, 65535)
        self.email_edit = QLineEdit()
        self.password_edit = QLineEdit()
        self.password_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.ssl_checkbox = QCheckBox("Use SSL/TLS")

        self.name_edit.setPlaceholderText("Friendly label e.g. 'Old Host' or 'Office 365'")
        self.server_edit.setPlaceholderText("imap.example.com")
        self.email_edit.setPlaceholderText("user@example.com")

        layout.addRow("Account name:", self.name_edit)
        layout.addRow("IMAP server:", self.server_edit)
        layout.addRow("Port:", self.port_spin)
        layout.addRow("Email address:", self.email_edit)
        layout.addRow("Password:", self.password_edit)
        layout.addRow("", self.ssl_checkbox)

        btn_box = QHBoxLayout()
        btn_box.setSpacing(10)
        btn_box.addStretch()
        self.btn_ok = QPushButton("Save")
        self.btn_cancel = QPushButton("Cancel")
        self.btn_ok.setDefault(True)
        btn_box.addWidget(self.btn_ok)
        btn_box.addWidget(self.btn_cancel)
        layout.addRow(btn_box)

        self.btn_ok.clicked.connect(self.accept)
        self.btn_cancel.clicked.connect(self.reject)

        if initial:
            self.name_edit.setText(initial.get("name", ""))
            self.server_edit.setText(initial.get("server", ""))
            self.port_spin.setValue(initial.get("port", 993))
            self.email_edit.setText(initial.get("email", ""))
            self.password_edit.setText(initial.get("password", ""))
            self.ssl_checkbox.setChecked(initial.get("use_ssl", True))
        else:
            self.port_spin.setValue(993)
            self.ssl_checkbox.setChecked(True)

    def get_data(self) -> Dict:
        return {
            "name": self.name_edit.text().strip(),
            "server": self.server_edit.text().strip(),
            "port": int(self.port_spin.value()),
            "email": self.email_edit.text().strip(),
            "password": self.password_edit.text(),
            "use_ssl": self.ssl_checkbox.isChecked(),
        }


class SyncSetupDialog(QDialog):
    def __init__(self, parent=None, accounts: List[Dict] = None,
                 initial: Optional[Dict] = None):
        super().__init__(parent)
        self.setWindowTitle("Sync Setup")
        self.resize(440, 260)

        self.accounts = accounts or []

        layout = QFormLayout(self)
        layout.setLabelAlignment(Qt.AlignmentFlag.AlignRight)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(12)

        self.name_edit = QLineEdit()
        self.from_combo = QComboBox()
        self.to_combo = QComboBox()
        self.active_checkbox = QCheckBox("Active")
        self.all_folders_checkbox = QCheckBox("Sync all folders")
        self.folders_edit = QLineEdit()
        self.folders_edit.setPlaceholderText("Comma-separated (e.g. INBOX,Sent)")

        for acc in self.accounts:
            label = f"{acc['name']} ({acc['email']})"
            self.from_combo.addItem(label, acc["id"])
            self.to_combo.addItem(label, acc["id"])

        layout.addRow("Setup name:", self.name_edit)
        layout.addRow("From account:", self.from_combo)
        layout.addRow("To account:", self.to_combo)
        layout.addRow("", self.active_checkbox)
        layout.addRow(self.all_folders_checkbox)
        layout.addRow("Specific folders:", self.folders_edit)

        btn_box = QHBoxLayout()
        btn_box.setSpacing(10)
        btn_box.addStretch()
        self.btn_ok = QPushButton("Save")
        self.btn_cancel = QPushButton("Cancel")
        self.btn_ok.setDefault(True)
        btn_box.addWidget(self.btn_ok)
        btn_box.addWidget(self.btn_cancel)
        layout.addRow(btn_box)

        self.all_folders_checkbox.setChecked(True)
        self.folders_edit.setEnabled(False)

        self.all_folders_checkbox.stateChanged.connect(self._toggle_folders_edit)

        self.btn_ok.clicked.connect(self.accept)
        self.btn_cancel.clicked.connect(self.reject)

        if initial:
            self.name_edit.setText(initial.get("name", ""))
            from_id = initial.get("from_account_id")
            to_id = initial.get("to_account_id")
            self._set_combo_by_data(self.from_combo, from_id)
            self._set_combo_by_data(self.to_combo, to_id)

            self.active_checkbox.setChecked(initial.get("active", True))
            folders = initial.get("folders")
            if folders:
                self.all_folders_checkbox.setChecked(False)
                self.folders_edit.setEnabled(True)
                self.folders_edit.setText(",".join(folders))
            else:
                self.all_folders_checkbox.setChecked(True)
                self.folders_edit.setEnabled(False)

    def _set_combo_by_data(self, combo: QComboBox, value: int):
        for i in range(combo.count()):
            if combo.itemData(i) == value:
                combo.setCurrentIndex(i)
                return

    def _toggle_folders_edit(self, state):
        self.folders_edit.setEnabled(not self.all_folders_checkbox.isChecked())

    def get_data(self) -> Dict:
        from_account_id = self.from_combo.currentData()
        to_account_id = self.to_combo.currentData()
        folders = None
        if not self.all_folders_checkbox.isChecked():
            text = self.folders_edit.text().strip()
            if text:
                folders = [f.strip() for f in text.split(",") if f.strip()]
        return {
            "name": self.name_edit.text().strip(),
            "from_account_id": from_account_id,
            "to_account_id": to_account_id,
            "active": self.active_checkbox.isChecked(),
            "folders": folders,
        }


# =============================================================================
# Main window / GUI
# =============================================================================

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("IMAP Sync Manager")
        self.resize(1000, 650)

        self.db = DatabaseManager()
        self.current_worker: Optional[SyncWorker] = None
        self.job_queue: List[int] = []

        self.tabs = QTabWidget()
        self.tabs.setDocumentMode(True)
        self.tabs.setTabPosition(QTabWidget.TabPosition.North)
        self.setCentralWidget(self.tabs)

        self._init_accounts_tab()
        self._init_sync_tab()
        self._init_status_tab()

        self._setup_status_bar()
        self._apply_modern_style()

        self._load_accounts()
        self._load_sync_setups()

    # ---------------- Styling ----------------

    def _apply_modern_style(self):
        # Slightly larger, clean font
        app = QApplication.instance()
        if app:
            font = QFont("Segoe UI", 9)
            app.setFont(font)

        # Table header styling
        for table in (self.accounts_table, self.sync_table):
            header = table.horizontalHeader()
            header.setHighlightSections(False)
            header.setStretchLastSection(True)
            header.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
            header.setDefaultSectionSize(150)

        # Buttons: minimum height
        all_buttons = [
            self.btn_add_account, self.btn_edit_account, self.btn_delete_account,
            self.btn_add_sync, self.btn_edit_sync, self.btn_delete_sync,
            self.btn_start_sync, self.btn_stop_sync, self.btn_save_log
        ]
        for btn in all_buttons:
            btn.setMinimumHeight(28)

    def _setup_status_bar(self):
        status = QStatusBar()
        status.showMessage("Ready")
        self.setStatusBar(status)
        self.status_bar = status

    # ---------------- Logging helper ----------------

    def log(self, message: str):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        line = f"[{timestamp}] {message}"
        self.log_view.appendPlainText(line)
        try:
            with open("imap_syncer.log", "a", encoding="utf-8") as f:
                f.write(line + "\n")
        except Exception:
            pass
        if hasattr(self, "status_bar"):
            self.status_bar.showMessage(message, 5000)

    # ---------------- IMAP credential test helper ----------------

    def _test_imap_credentials(self, data: Dict) -> bool:
        """
        Test connection and login with given account data.
        Returns True if login succeeds, False if it fails.
        Shows appropriate message boxes and logs.
        """
        server = data["server"]
        port = data["port"]
        use_ssl = data["use_ssl"]
        email = data["email"]
        password = data["password"]

        if not password:
            # Allow saving accounts without testing if no password is given
            return True

        try:
            self.log(f"Testing IMAP connection to {server}:{port} (ssl={use_ssl}) for {email}")
            client = IMAPClient(server, port=port, ssl=use_ssl)
            client.login(email, password)
            client.logout()
            QMessageBox.information(
                self,
                "Connection test",
                f"Successfully connected to {server} as {email}."
            )
            return True

        except socket.gaierror:
            msg = (
                "DNS lookup failed for the IMAP server.\n\n"
                "Check that the server hostname is correct."
            )
            QMessageBox.critical(self, "Connection test failed", msg)
            self.log(f"IMAP test failed for {email}: DNS error")
            return False

        except Exception as e:
            msg = f"Connection or login failed:\n\n{e}"
            if "socket error: EOF" in str(e):
                msg += (
                    "\n\nHint: 'socket error: EOF' often means the IMAP server "
                    "closed the connection immediately. Check that:\n"
                    "- The IMAP server host is correct (IMAP, not POP or webmail)\n"
                    "- The port matches the SSL setting (e.g. 993 with SSL, 143 without)\n"
                    "- IMAP is enabled on the server\n"
                )
            QMessageBox.critical(self, "Connection test failed", msg)
            self.log(f"IMAP test failed for {email}: {e}")
            return False

    # ---------------- Accounts tab ----------------

    def _init_accounts_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(10)

        title = QLabel("IMAP Accounts")
        title.setStyleSheet("font-size: 16px; font-weight: 600;")
        layout.addWidget(title)

        self.accounts_table = QTableWidget()
        self.accounts_table.setColumnCount(5)
        self.accounts_table.setHorizontalHeaderLabels(
            ["ID", "Name", "Server", "Email", "SSL/TLS"]
        )
        self.accounts_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.accounts_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.accounts_table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.accounts_table.verticalHeader().setVisible(False)
        self.accounts_table.setAlternatingRowColors(True)
        self.accounts_table.setShowGrid(False)

        btn_layout = QHBoxLayout()
        btn_layout.setSpacing(8)
        self.btn_add_account = QPushButton("Add account")
        self.btn_edit_account = QPushButton("Edit selected")
        self.btn_delete_account = QPushButton("Delete selected")
        btn_layout.addWidget(self.btn_add_account)
        btn_layout.addWidget(self.btn_edit_account)
        btn_layout.addWidget(self.btn_delete_account)
        btn_layout.addStretch()

        layout.addWidget(self.accounts_table)
        layout.addLayout(btn_layout)

        self.tabs.addTab(tab, "Accounts")

        self.btn_add_account.clicked.connect(self.add_account)
        self.btn_edit_account.clicked.connect(self.edit_account)
        self.btn_delete_account.clicked.connect(self.delete_account)

    def _load_accounts(self):
        accounts = self.db.get_accounts()
        self.accounts_table.setRowCount(len(accounts))
        for row, acc in enumerate(accounts):
            self.accounts_table.setItem(row, 0, QTableWidgetItem(str(acc["id"])))
            self.accounts_table.setItem(row, 1, QTableWidgetItem(acc["name"]))
            self.accounts_table.setItem(row, 2, QTableWidgetItem(f"{acc['server']}:{acc['port']}"))
            self.accounts_table.setItem(row, 3, QTableWidgetItem(acc["email"]))
            self.accounts_table.setItem(row, 4, QTableWidgetItem("Yes" if acc["use_ssl"] else "No"))

        self.accounts_table.resizeColumnsToContents()

    def _get_selected_account_id(self) -> Optional[int]:
        sel = self.accounts_table.selectedItems()
        if not sel:
            return None
        row = self.accounts_table.currentRow()
        id_item = self.accounts_table.item(row, 0)
        return int(id_item.text()) if id_item else None

    def add_account(self):
        dlg = AccountDialog(self)
        if dlg.exec() == QDialog.DialogCode.Accepted:
            data = dlg.get_data()
            if not data["name"] or not data["server"] or not data["email"]:
                QMessageBox.warning(self, "Validation", "Name, server and email are required.")
                return

            ok = self._test_imap_credentials(data)
            if not ok:
                res = QMessageBox.question(
                    self,
                    "Save account anyway?",
                    "The connection test failed.\n\n"
                    "Do you still want to save this account?",
                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
                )
                if res != QMessageBox.StandardButton.Yes:
                    return

            self.db.add_account(**data)
            self._load_accounts()
            self._load_sync_setups()

    def edit_account(self):
        acc_id = self._get_selected_account_id()
        if acc_id is None:
            QMessageBox.information(self, "Edit account", "Please select an account first.")
            return
        acc = self.db.get_account(acc_id)
        if not acc:
            QMessageBox.warning(self, "Error", "Account not found.")
            return
        dlg = AccountDialog(self, initial=acc)
        if dlg.exec() == QDialog.DialogCode.Accepted:
            data = dlg.get_data()
            if not data["name"] or not data["server"] or not data["email"]:
                QMessageBox.warning(self, "Validation", "Name, server and email are required.")
                return

            ok = self._test_imap_credentials(data)
            if not ok:
                res = QMessageBox.question(
                    self,
                    "Save account anyway?",
                    "The connection test failed.\n\n"
                    "Do you still want to save these settings?",
                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
                )
                if res != QMessageBox.StandardButton.Yes:
                    return

            self.db.update_account(acc_id, **data)
            self._load_accounts()
            self._load_sync_setups()

    def delete_account(self):
        acc_id = self._get_selected_account_id()
        if acc_id is None:
            QMessageBox.information(self, "Delete account", "Please select an account first.")
            return
        if QMessageBox.question(
                self, "Confirm delete",
                "Delete selected account? This will also break related sync setups.",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        ) == QMessageBox.StandardButton.Yes:
            self.db.delete_account(acc_id)
            self._load_accounts()
            self._load_sync_setups()

    # ---------------- Sync setups tab ----------------

    def _init_sync_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(10)

        title = QLabel("Sync Setups")
        title.setStyleSheet("font-size: 16px; font-weight: 600;")
        layout.addWidget(title)

        self.sync_table = QTableWidget()
        self.sync_table.setColumnCount(7)
        self.sync_table.setHorizontalHeaderLabels(
            ["ID", "Name", "From", "To", "Folders", "Active", "Last Run"]
        )
        self.sync_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.sync_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.sync_table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.sync_table.verticalHeader().setVisible(False)
        self.sync_table.setAlternatingRowColors(True)
        self.sync_table.setShowGrid(False)

        btn_layout = QHBoxLayout()
        btn_layout.setSpacing(8)
        self.btn_add_sync = QPushButton("Add sync setup")
        self.btn_edit_sync = QPushButton("Edit selected")
        self.btn_delete_sync = QPushButton("Delete selected")
        self.btn_start_sync = QPushButton("Start selected")
        self.btn_stop_sync = QPushButton("Stop current")
        btn_layout.addWidget(self.btn_add_sync)
        btn_layout.addWidget(self.btn_edit_sync)
        btn_layout.addWidget(self.btn_delete_sync)
        btn_layout.addStretch()
        btn_layout.addWidget(self.btn_start_sync)
        btn_layout.addWidget(self.btn_stop_sync)

        layout.addWidget(self.sync_table)
        layout.addLayout(btn_layout)

        self.tabs.addTab(tab, "Sync setups")

        self.btn_add_sync.clicked.connect(self.add_sync_setup)
        self.btn_edit_sync.clicked.connect(self.edit_sync_setup)
        self.btn_delete_sync.clicked.connect(self.delete_sync_setup)
        self.btn_start_sync.clicked.connect(self.start_selected_sync)
        self.btn_stop_sync.clicked.connect(self.stop_current_sync)

    def _load_sync_setups(self):
        setups = self.db.get_sync_setups()
        accounts = {a["id"]: a for a in self.db.get_accounts()}
        self.sync_table.setRowCount(len(setups))
        for row, s in enumerate(setups):
            from_acc = accounts.get(s["from_account_id"])
            to_acc = accounts.get(s["to_account_id"])
            from_label = from_acc["name"] if from_acc else "?"
            to_label = to_acc["name"] if to_acc else "?"
            folders = s["folders"]
            folders_text = "All" if not folders else ", ".join(folders)
            self.sync_table.setItem(row, 0, QTableWidgetItem(str(s["id"])))
            self.sync_table.setItem(row, 1, QTableWidgetItem(s["name"]))
            self.sync_table.setItem(row, 2, QTableWidgetItem(from_label))
            self.sync_table.setItem(row, 3, QTableWidgetItem(to_label))
            self.sync_table.setItem(row, 4, QTableWidgetItem(folders_text))
            self.sync_table.setItem(row, 5, QTableWidgetItem("Yes" if s["active"] else "No"))
            self.sync_table.setItem(row, 6, QTableWidgetItem(s["last_run"] or ""))

        self.sync_table.resizeColumnsToContents()

    def _get_selected_setup_id(self) -> Optional[int]:
        sel = self.sync_table.selectedItems()
        if not sel:
            return None
        row = self.sync_table.currentRow()
        id_item = self.sync_table.item(row, 0)
        return int(id_item.text()) if id_item else None

    def add_sync_setup(self):
        accounts = self.db.get_accounts()
        if len(accounts) < 2:
            QMessageBox.information(
                self, "Need accounts",
                "Please configure at least two IMAP accounts before creating a sync setup."
            )
            return
        dlg = SyncSetupDialog(self, accounts=accounts)
        if dlg.exec() == QDialog.DialogCode.Accepted:
            data = dlg.get_data()
            if not data["name"]:
                QMessageBox.warning(self, "Validation", "Setup name is required.")
                return
            if data["from_account_id"] == data["to_account_id"]:
                QMessageBox.warning(self, "Validation", "From and To accounts must differ.")
                return
            self.db.add_sync_setup(
                data["name"],
                data["from_account_id"],
                data["to_account_id"],
                data["folders"],
                data["active"],
            )
            self._load_sync_setups()

    def edit_sync_setup(self):
        setup_id = self._get_selected_setup_id()
        if setup_id is None:
            QMessageBox.information(self, "Edit sync", "Please select a sync setup first.")
            return
        setup = self.db.get_sync_setup(setup_id)
        if not setup:
            QMessageBox.warning(self, "Error", "Sync setup not found.")
            return
        accounts = self.db.get_accounts()
        dlg = SyncSetupDialog(self, accounts=accounts, initial=setup)
        if dlg.exec() == QDialog.DialogCode.Accepted:
            data = dlg.get_data()
            if not data["name"]:
                QMessageBox.warning(self, "Validation", "Setup name is required.")
                return
            if data["from_account_id"] == data["to_account_id"]:
                QMessageBox.warning(self, "Validation", "From and To accounts must differ.")
                return
            self.db.update_sync_setup(
                setup_id,
                data["name"],
                data["from_account_id"],
                data["to_account_id"],
                data["folders"],
                data["active"],
            )
            self._load_sync_setups()

    def delete_sync_setup(self):
        setup_id = self._get_selected_setup_id()
        if setup_id is None:
            QMessageBox.information(self, "Delete sync", "Please select a sync setup first.")
            return
        if QMessageBox.question(
                self, "Confirm delete",
                "Delete selected sync setup and its sync history?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        ) == QMessageBox.StandardButton.Yes:
            self.db.delete_sync_setup(setup_id)
            self._load_sync_setups()

    # ---------------- Status tab ----------------

    def _init_status_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(10)

        title = QLabel("Status & Logs")
        title.setStyleSheet("font-size: 16px; font-weight: 600;")
        layout.addWidget(title)

        self.current_job_label = QLabel("No sync running.")
        self.current_job_label.setStyleSheet("font-weight: 500;")
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        self.progress_bar.setTextVisible(True)

        self.log_view = QPlainTextEdit()
        self.log_view.setReadOnly(True)
        self.log_view.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)

        btn_layout = QHBoxLayout()
        btn_layout.setSpacing(8)
        self.btn_save_log = QPushButton("Save log to file...")
        btn_layout.addWidget(self.btn_save_log)
        btn_layout.addStretch()

        layout.addWidget(self.current_job_label)
        layout.addWidget(self.progress_bar)
        layout.addWidget(self.log_view)
        layout.addLayout(btn_layout)

        self.tabs.addTab(tab, "Status / Logs")

        self.btn_save_log.clicked.connect(self.save_log_to_file)

    def save_log_to_file(self):
        path, _ = QFileDialog.getSaveFileName(
            self,
            "Save log",
            "imap_syncer.log",
            "Log files (*.log);;All files (*.*)"
        )
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write(self.log_view.toPlainText())
            QMessageBox.information(self, "Saved", f"Log saved to {path}")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to save log: {e}")

    # ---------------- Start/stop sync & queue ----------------

    def start_selected_sync(self):
        setup_id = self._get_selected_setup_id()
        if setup_id is None:
            QMessageBox.information(self, "Start sync", "Please select a sync setup first.")
            return

        setup = self.db.get_sync_setup(setup_id)
        if not setup or not setup["active"]:
            QMessageBox.information(self, "Inactive", "Selected sync setup is inactive or not found.")
            return

        self.job_queue.append(setup_id)
        self.log(f"Queued sync setup #{setup_id}: {setup['name']}")
        if not self.current_worker:
            self._start_next_job_in_queue()

    def _start_next_job_in_queue(self):
        if self.current_worker or not self.job_queue:
            return
        setup_id = self.job_queue.pop(0)
        setup = self.db.get_sync_setup(setup_id)
        if not setup:
            self.log(f"Skipped missing sync setup #{setup_id}.")
            self._start_next_job_in_queue()
            return

        self.current_job_label.setText(f"Running: {setup['name']} (ID {setup_id})")
        self.progress_bar.setValue(0)
        self.current_worker = SyncWorker(self.db.db_path, setup_id)
        self.current_worker.progress.connect(self.on_worker_progress)
        self.current_worker.status.connect(self.log)
        self.current_worker.error.connect(self.on_worker_error)
        self.current_worker.finished.connect(self.on_worker_finished)
        self.current_worker.start()
        self.log(f"Started sync setup #{setup_id}: {setup['name']}")

    def stop_current_sync(self):
        if self.current_worker:
            self.log("Stop requested for current sync.")
            self.current_worker.request_stop()
        else:
            QMessageBox.information(self, "Stop", "No sync is currently running.")

    def on_worker_progress(self, current: int, total: int, status_text: str):
        self.current_job_label.setText(status_text)
        if total > 0:
            pct = int((current / total) * 100)
            self.progress_bar.setValue(pct)
        else:
            self.progress_bar.setValue(0)

    def on_worker_error(self, setup_id: int, message: str):
        self.log(f"Error in sync #{setup_id}: {message}")
        QMessageBox.critical(self, "Sync error", f"Error during sync #{setup_id}:\n\n{message}")

    def on_worker_finished(self, setup_id: int):
        self.log(f"Sync #{setup_id} finished.")
        self.current_worker = None
        self._load_sync_setups()
        self.current_job_label.setText("No sync running.")
        self.progress_bar.setValue(0)
        self._start_next_job_in_queue()


# =============================================================================
# Entry point
# =============================================================================

def apply_dark_palette(app: QApplication):
    app.setStyle(QStyleFactory.create("Fusion"))
    palette = QPalette()

    palette.setColor(QPalette.ColorRole.Window, QColor(30, 30, 30))
    palette.setColor(QPalette.ColorRole.WindowText, QColor(220, 220, 220))
    palette.setColor(QPalette.ColorRole.Base, QColor(25, 25, 25))
    palette.setColor(QPalette.ColorRole.AlternateBase, QColor(40, 40, 40))
    palette.setColor(QPalette.ColorRole.ToolTipBase, QColor(220, 220, 220))
    palette.setColor(QPalette.ColorRole.ToolTipText, QColor(220, 220, 220))
    palette.setColor(QPalette.ColorRole.Text, QColor(220, 220, 220))
    palette.setColor(QPalette.ColorRole.Button, QColor(45, 45, 45))
    palette.setColor(QPalette.ColorRole.ButtonText, QColor(220, 220, 220))
    palette.setColor(QPalette.ColorRole.BrightText, QColor(255, 0, 0))
    palette.setColor(QPalette.ColorRole.Highlight, QColor(100, 149, 237))
    palette.setColor(QPalette.ColorRole.HighlightedText, QColor(255, 255, 255))

    app.setPalette(palette)


def main():
    app = QApplication(sys.argv)
    apply_dark_palette(app)

    window = MainWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()