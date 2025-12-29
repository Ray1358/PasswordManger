import os
import base64
import sqlite3
from dataclasses import dataclass
from typing import Optional, List, Tuple

import tkinter as tk
from tkinter import ttk, messagebox

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet, InvalidToken


DB_PATH = "vault.db"
KDF_ITERATIONS = 390_000


# =========================
# DB + CRYPTO
# =========================
def connect(db_path: str = DB_PATH) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


def init_db(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS meta (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            salt BLOB NOT NULL
        );
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS entries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            site TEXT NOT NULL,
            username TEXT NOT NULL,
            password_enc BLOB NOT NULL,
            notes TEXT DEFAULT '',
            created_at TEXT DEFAULT (datetime('now')),
            updated_at TEXT DEFAULT (datetime('now'))
        );
        """
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_entries_site ON entries(site);")
    conn.commit()


def get_or_create_salt(conn: sqlite3.Connection) -> bytes:
    row = conn.execute("SELECT salt FROM meta WHERE id = 1;").fetchone()
    if row:
        return row[0]
    salt = os.urandom(16)
    conn.execute("INSERT INTO meta (id, salt) VALUES (1, ?);", (salt,))
    conn.commit()
    return salt


def derive_key(master_password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=KDF_ITERATIONS,
    )
    key = kdf.derive(master_password.encode("utf-8"))
    return base64.urlsafe_b64encode(key)


def make_fernet(master_password: str, salt: bytes) -> Fernet:
    return Fernet(derive_key(master_password, salt))


def encrypt(fernet: Fernet, plaintext: str) -> bytes:
    return fernet.encrypt(plaintext.encode("utf-8"))


def decrypt(fernet: Fernet, ciphertext: bytes) -> str:
    return fernet.decrypt(ciphertext).decode("utf-8")


def add_entry(conn: sqlite3.Connection, fernet: Fernet, site: str, username: str, password: str, notes: str = "") -> None:
    site = site.strip()
    username = username.strip()
    if not site or not username:
        raise ValueError("Site and username are required.")
    if not password:
        raise ValueError("Password cannot be empty.")

    pw_enc = encrypt(fernet, password)
    conn.execute(
        "INSERT INTO entries (site, username, password_enc, notes) VALUES (?, ?, ?, ?);",
        (site, username, pw_enc, (notes or "").strip()),
    )
    conn.commit()


def list_entries(conn: sqlite3.Connection) -> List[Tuple[int, str, str, str]]:
    return conn.execute(
        "SELECT id, site, username, updated_at FROM entries ORDER BY updated_at DESC;"
    ).fetchall()


def search_entries(conn: sqlite3.Connection, query: str) -> List[Tuple[int, str, str, str]]:
    q = f"%{query.strip()}%"
    return conn.execute(
        """
        SELECT id, site, username, updated_at
        FROM entries
        WHERE site LIKE ? OR username LIKE ?
        ORDER BY updated_at DESC;
        """,
        (q, q),
    ).fetchall()


def get_entry(conn: sqlite3.Connection, entry_id: int) -> Optional[Tuple[int, str, str, bytes, str]]:
    return conn.execute(
        "SELECT id, site, username, password_enc, notes FROM entries WHERE id = ?;",
        (entry_id,),
    ).fetchone()


def update_entry(conn: sqlite3.Connection, fernet: Fernet, entry_id: int, new_password: Optional[str], new_notes: Optional[str]) -> None:
    updates = []
    params = []

    if new_password is not None:
        if new_password == "":
            raise ValueError("New password cannot be empty.")
        updates.append("password_enc = ?")
        params.append(encrypt(fernet, new_password))

    if new_notes is not None:
        updates.append("notes = ?")
        params.append(new_notes)

    if not updates:
        return

    updates.append("updated_at = datetime('now')")
    sql = f"UPDATE entries SET {', '.join(updates)} WHERE id = ?;"
    params.append(entry_id)

    conn.execute(sql, tuple(params))
    conn.commit()


def delete_entry(conn: sqlite3.Connection, entry_id: int) -> None:
    conn.execute("DELETE FROM entries WHERE id = ?;", (entry_id,))
    conn.commit()


# =========================
# UI
# =========================
class PasswordVaultUI:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("Password Vault (SQLite + Encryption)")
        self.root.geometry("980x580")

        self.conn = connect(DB_PATH)
        init_db(self.conn)
        self.salt = get_or_create_salt(self.conn)

        self.fernet: Optional[Fernet] = None

        # Top unlock bar
        unlock_frame = ttk.Frame(root, padding=10)
        unlock_frame.pack(fill="x")

        ttk.Label(unlock_frame, text="Master Password:").pack(side="left")
        self.master_entry = ttk.Entry(unlock_frame, show="*", width=28)
        self.master_entry.pack(side="left", padx=(8, 8))
        self.unlock_btn = ttk.Button(unlock_frame, text="Unlock", command=self.unlock)
        self.unlock_btn.pack(side="left")
        self.lock_btn = ttk.Button(unlock_frame, text="Lock", command=self.lock, state="disabled")
        self.lock_btn.pack(side="left", padx=(8, 0))

        self.status_var = tk.StringVar(value="Locked. Enter master password to unlock.")
        ttk.Label(unlock_frame, textvariable=self.status_var).pack(side="left", padx=(16, 0))

        # Main content
        content = ttk.Frame(root, padding=10)
        content.pack(fill="both", expand=True)

        # Left panel: form + actions
        left = ttk.Frame(content)
        left.pack(side="left", fill="y", padx=(0, 10))

        form = ttk.LabelFrame(left, text="Add / Update Entry", padding=10)
        form.pack(fill="x")

        self.site_var = tk.StringVar()
        self.user_var = tk.StringVar()
        self.pass_var = tk.StringVar()
        self.notes_var = tk.StringVar()

        ttk.Label(form, text="Site:").grid(row=0, column=0, sticky="w")
        ttk.Entry(form, textvariable=self.site_var, width=30).grid(row=0, column=1, pady=4, sticky="ew")

        ttk.Label(form, text="Username:").grid(row=1, column=0, sticky="w")
        ttk.Entry(form, textvariable=self.user_var, width=30).grid(row=1, column=1, pady=4, sticky="ew")

        ttk.Label(form, text="Password:").grid(row=2, column=0, sticky="w")
        ttk.Entry(form, textvariable=self.pass_var, show="*", width=30).grid(row=2, column=1, pady=4, sticky="ew")

        ttk.Label(form, text="Notes:").grid(row=3, column=0, sticky="w")
        ttk.Entry(form, textvariable=self.notes_var, width=30).grid(row=3, column=1, pady=4, sticky="ew")

        form.columnconfigure(1, weight=1)

        btns = ttk.Frame(left)
        btns.pack(fill="x", pady=(10, 0))

        self.add_btn = ttk.Button(btns, text="Add", command=self.add_entry_ui, state="disabled")
        self.add_btn.pack(fill="x", pady=3)

        self.update_btn = ttk.Button(btns, text="Update Selected", command=self.update_selected_ui, state="disabled")
        self.update_btn.pack(fill="x", pady=3)

        self.delete_btn = ttk.Button(btns, text="Delete Selected", command=self.delete_selected_ui, state="disabled")
        self.delete_btn.pack(fill="x", pady=3)

        self.view_btn = ttk.Button(btns, text="View (Decrypt) Selected", command=self.view_selected_ui, state="disabled")
        self.view_btn.pack(fill="x", pady=3)

        # Search
        search_box = ttk.LabelFrame(left, text="Search", padding=10)
        search_box.pack(fill="x", pady=(10, 0))

        self.search_var = tk.StringVar()
        ttk.Entry(search_box, textvariable=self.search_var).pack(fill="x")
        self.search_btn = ttk.Button(search_box, text="Search", command=self.search_ui, state="disabled")
        self.search_btn.pack(fill="x", pady=(8, 0))

        self.refresh_btn = ttk.Button(search_box, text="Refresh List", command=self.refresh_ui, state="disabled")
        self.refresh_btn.pack(fill="x", pady=(6, 0))

        # Right panel: table
        right = ttk.Frame(content)
        right.pack(side="left", fill="both", expand=True)

        table_frame = ttk.LabelFrame(right, text="Entries", padding=10)
        table_frame.pack(fill="both", expand=True)

        cols = ("id", "site", "username", "updated_at")
        self.tree = ttk.Treeview(table_frame, columns=cols, show="headings", height=18)
        self.tree.heading("id", text="ID")
        self.tree.heading("site", text="Site")
        self.tree.heading("username", text="Username")
        self.tree.heading("updated_at", text="Updated")

        self.tree.column("id", width=60, anchor="center")
        self.tree.column("site", width=260)
        self.tree.column("username", width=260)
        self.tree.column("updated_at", width=160)

        yscroll = ttk.Scrollbar(table_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=yscroll.set)

        self.tree.pack(side="left", fill="both", expand=True)
        yscroll.pack(side="left", fill="y")

        self.tree.bind("<<TreeviewSelect>>", self.on_select)

        # Start locked
        self.set_locked_state(True)

    def set_locked_state(self, locked: bool) -> None:
        state = "disabled" if locked else "normal"
        for b in (self.add_btn, self.update_btn, self.delete_btn, self.view_btn, self.search_btn, self.refresh_btn):
            b.configure(state=state)
        self.lock_btn.configure(state=("normal" if not locked else "disabled"))
        self.unlock_btn.configure(state=("normal" if locked else "disabled"))
        self.master_entry.configure(state=("normal" if locked else "disabled"))

        if locked:
            self.tree.delete(*self.tree.get_children())
            self.status_var.set("Locked. Enter master password to unlock.")
            self.fernet = None

    def unlock(self) -> None:
        mp = self.master_entry.get()
        if not mp:
            messagebox.showerror("Unlock Failed", "Master password cannot be empty.")
            return
        try:
            f = make_fernet(mp, self.salt)

            # quick validation if there are entries: try decrypting one
            row = self.conn.execute("SELECT password_enc FROM entries LIMIT 1;").fetchone()
            if row:
                _ = decrypt(f, row[0])  # will raise if wrong password

            self.fernet = f
            self.set_locked_state(False)
            self.status_var.set("Unlocked ✅")
            self.refresh_ui()
        except InvalidToken:
            messagebox.showerror("Unlock Failed", "Wrong master password.")
        except Exception as e:
            messagebox.showerror("Unlock Failed", str(e))

    def lock(self) -> None:
        self.master_entry.delete(0, tk.END)
        self.set_locked_state(True)

    def refresh_ui(self) -> None:
        self.tree.delete(*self.tree.get_children())
        for (i, site, user, updated) in list_entries(self.conn):
            self.tree.insert("", "end", values=(i, site, user, updated))

    def search_ui(self) -> None:
        q = self.search_var.get().strip()
        if not q:
            self.refresh_ui()
            return
        self.tree.delete(*self.tree.get_children())
        for (i, site, user, updated) in search_entries(self.conn, q):
            self.tree.insert("", "end", values=(i, site, user, updated))

    def on_select(self, _event=None) -> None:
        # Enable update/delete/view only when unlocked and an item is selected
        if self.fernet is None:
            return
        sel = self.get_selected_id()
        if sel is None:
            return
        # Prefill site/user/notes for convenience (do not prefill decrypted password automatically)
        row = get_entry(self.conn, sel)
        if row:
            _, site, user, _, notes = row
            self.site_var.set(site)
            self.user_var.set(user)
            self.notes_var.set(notes or "")
            self.pass_var.set("")

    def get_selected_id(self) -> Optional[int]:
        selection = self.tree.selection()
        if not selection:
            return None
        values = self.tree.item(selection[0], "values")
        if not values:
            return None
        return int(values[0])

    def add_entry_ui(self) -> None:
        if self.fernet is None:
            return
        try:
            add_entry(
                self.conn,
                self.fernet,
                self.site_var.get(),
                self.user_var.get(),
                self.pass_var.get(),
                self.notes_var.get(),
            )
            self.status_var.set("Saved ✅")
            self.clear_form(keep_site_user=False)
            self.refresh_ui()
        except Exception as e:
            messagebox.showerror("Add Failed", str(e))

    def update_selected_ui(self) -> None:
        if self.fernet is None:
            return
        entry_id = self.get_selected_id()
        if entry_id is None:
            messagebox.showinfo("Update", "Select an entry first.")
            return

        # Only update fields the user actually wants to change
        new_pw = self.pass_var.get().strip()
        new_pw_val = new_pw if new_pw != "" else None
        new_notes_val = self.notes_var.get()  # allow empty notes update

        try:
            update_entry(self.conn, self.fernet, entry_id, new_pw_val, new_notes_val)
            self.status_var.set("Updated ✅")
            self.pass_var.set("")
            self.refresh_ui()
        except Exception as e:
            messagebox.showerror("Update Failed", str(e))

    def delete_selected_ui(self) -> None:
        entry_id = self.get_selected_id()
        if entry_id is None:
            messagebox.showinfo("Delete", "Select an entry first.")
            return
        if not messagebox.askyesno("Confirm Delete", f"Delete entry ID {entry_id}?"):
            return
        try:
            delete_entry(self.conn, entry_id)
            self.status_var.set("Deleted ✅")
            self.clear_form(keep_site_user=False)
            self.refresh_ui()
        except Exception as e:
            messagebox.showerror("Delete Failed", str(e))

    def view_selected_ui(self) -> None:
        if self.fernet is None:
            return
        entry_id = self.get_selected_id()
        if entry_id is None:
            messagebox.showinfo("View", "Select an entry first.")
            return

        row = get_entry(self.conn, entry_id)
        if not row:
            messagebox.showerror("View", "Entry not found.")
            return

        try:
            _, site, user, pw_enc, notes = row
            pw = decrypt(self.fernet, pw_enc)
        except InvalidToken:
            messagebox.showerror("Decrypt Failed", "Wrong master password or corrupted data.")
            return

        # Show in dialog with a copy button
        top = tk.Toplevel(self.root)
        top.title(f"Entry {entry_id}")
        top.geometry("520x260")

        frm = ttk.Frame(top, padding=12)
        frm.pack(fill="both", expand=True)

        ttk.Label(frm, text=f"Site: {site}").pack(anchor="w")
        ttk.Label(frm, text=f"Username: {user}").pack(anchor="w", pady=(4, 0))

        pw_frame = ttk.Frame(frm)
        pw_frame.pack(fill="x", pady=(10, 0))
        ttk.Label(pw_frame, text="Password:").pack(side="left")

        pw_var = tk.StringVar(value=pw)
        pw_entry = ttk.Entry(pw_frame, textvariable=pw_var, width=40)
        pw_entry.pack(side="left", padx=(8, 8), fill="x", expand=True)

        def copy_pw():
            self.root.clipboard_clear()
            self.root.clipboard_append(pw_var.get())
            messagebox.showinfo("Copied", "Password copied to clipboard.")

        ttk.Button(pw_frame, text="Copy", command=copy_pw).pack(side="left")

        ttk.Label(frm, text="Notes:").pack(anchor="w", pady=(12, 0))
        notes_box = tk.Text(frm, height=4, wrap="word")
        notes_box.pack(fill="both", expand=True)
        notes_box.insert("1.0", notes or "")
        notes_box.configure(state="disabled")

    def clear_form(self, keep_site_user: bool) -> None:
        if not keep_site_user:
            self.site_var.set("")
            self.user_var.set("")
        self.pass_var.set("")
        self.notes_var.set("")


def main():
    root = tk.Tk()
    # Use a nicer default theme if available
    try:
        style = ttk.Style()
        if "clam" in style.theme_names():
            style.theme_use("clam")
    except Exception:
        pass

    app = PasswordVaultUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
