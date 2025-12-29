Password Vault (Python)

A local desktop password manager built with Python that securely stores credentials using encryption.
The application uses a graphical user interface (GUI) and a local SQLite database to manage passwords safely on the user’s machine.

FEATURES
- Secure password storage using strong encryption (Fernet / AES)
- Master password required to unlock the vault
- Add, view, update, and delete saved credentials
- Search functionality by site or username
- Local SQLite database (no cloud storage)
- Desktop graphical user interface built with Tkinter

TECH STACK
- Python 3
- Tkinter (desktop GUI)
- SQLite
- cryptography (Fernet encryption)
- Virtual environments for dependency isolation

PROJECT STRUCTURE
password-vault/
- password_vault_ui.py   : Main application and UI logic
- requirements.txt       : Python dependencies
- README.md              : Project documentation
- .gitignore             : Ignored files (database, venv, cache)

HOW IT WORKS
- On first run, the application creates a local SQLite database.
- A random salt is generated and stored securely.
- The master password is used with PBKDF2 to derive an encryption key.
- Passwords are encrypted before being written to the database.
- Decryption only occurs in memory after successful unlock.

HOW TO RUN
1. Create and activate a virtual environment
2. Install dependencies:
   pip install -r requirements.txt
3. Run the application:
   python password_vault_ui.py

SECURITY NOTES
- The master password is never stored.
- All passwords are encrypted at rest.
- The database file (vault.db) is excluded from version control.
- This project is intended for educational and portfolio use.

WHAT I LEARNED
- Implementing encryption correctly using established libraries
- Secure credential storage practices
- Building desktop GUIs with Tkinter
- Integrating SQLite with Python applications
- Managing Python projects using virtual environments

FUTURE IMPROVEMENTS
- Password generator
- Auto-lock after inactivity
- Clipboard auto-clear for copied passwords
- Export/import functionality
- Dark mode UI

AUTHOR
Ramon Baez
Computer Science Student | Python Developer

<img width="432" height="644" alt="image" src="https://github.com/user-attachments/assets/e2df4c22-8dc1-4d4a-8385-0874f2158e80" />
