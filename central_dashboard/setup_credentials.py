#!/usr/bin/env python3
"""
Sentrium Enterprise — Credential Setup Script
=============================================
Creates individual user accounts using email addresses.
Multiple users can share the same department.
Passwords are hashed with bcrypt (rounds=12). TOTP is disabled.

Usage:
    python setup_credentials.py

Add as many users as needed. When done, type 'done' at the email prompt.
Output is the SENTRIUM_USERS_JSON value — paste it into Railway Variables.
"""
import json
import getpass
import re
import sys

try:
    import bcrypt
except ImportError:
    print("ERROR: bcrypt not installed. Run: pip install bcrypt")
    sys.exit(1)

DEPARTMENTS = [
    "All",
    "Security Operations",
    "Security Testing",
    "Security Engineering",
    "Research and Intelligence",
    "IT Infrastructure",
    "Operations",
    "Finance",
    "Sales",
    "Customer Success",
    "Brand & Marketing",
    "People and Culture",
    "Portfolio Management",
]

def hash_password(plain: str) -> str:
    return bcrypt.hashpw(plain.encode(), bcrypt.gensalt(rounds=12)).decode()

def is_valid_email(email: str) -> bool:
    return bool(re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', email.strip()))

def pick_department() -> str:
    print("\n    Departments:")
    for i, dept in enumerate(DEPARTMENTS, 1):
        print(f"      {i:>2}. {dept}")
    while True:
        choice = input("    Select department number: ").strip()
        if choice.isdigit() and 1 <= int(choice) <= len(DEPARTMENTS):
            return DEPARTMENTS[int(choice) - 1]
        print("    ✗ Invalid choice. Enter a number from the list.")

def pick_role() -> str:
    while True:
        role = input("    Role [1=staff  2=admin] (default: 1): ").strip()
        if role in ('', '1'):
            return 'dept_user'
        if role == '2':
            return 'admin'
        print("    ✗ Enter 1 or 2.")

def main():
    print("\n" + "="*62)
    print("  Sentrium Enterprise — User Credential Setup")
    print("  Email-based accounts | bcrypt (rounds=12) | TOTP disabled")
    print("="*62)
    print("  Type 'done' at the email prompt when finished.\n")

    users = []
    added_emails = set()

    while True:
        print(f"  ── User #{len(users)+1} " + "─"*40)
        email = input("  Email address (or 'done' to finish): ").strip().lower()

        if email == 'done':
            if not users:
                print("  ✗ No users added. Add at least one user.\n")
                continue
            break

        if not is_valid_email(email):
            print("  ✗ Invalid email format. Try again.\n")
            continue

        if email in added_emails:
            print(f"  ✗ {email} already added. Use a different email.\n")
            continue

        department = pick_department()
        role = pick_role()

        while True:
            pw  = getpass.getpass("    Password (min 10 chars): ")
            pw2 = getpass.getpass("    Confirm password       : ")
            if not pw:
                print("    ✗ Password cannot be empty.\n"); continue
            if len(pw) < 10:
                print("    ✗ Minimum 10 characters.\n"); continue
            if pw != pw2:
                print("    ✗ Passwords do not match.\n"); continue
            break

        hashed = hash_password(pw)
        users.append({
            "username":   email,
            "hash":       hashed,
            "department": department,
            "role":       role,
        })
        added_emails.add(email)
        print(f"  ✓ {email} ({department}) added.\n")

    # Summary
    print("\n" + "="*62)
    print(f"  {len(users)} user(s) created:\n")
    for u in users:
        tag = " [ADMIN]" if u["role"] == "admin" else ""
        print(f"    • {u['username']:<35} {u['department']}{tag}")

    json_value = json.dumps(users, separators=(',', ':'))

    print("\n" + "="*62)
    print("  Paste this into Railway as:  SENTRIUM_USERS_JSON")
    print("="*62 + "\n")
    print(json_value + "\n")

    # Save locally too (gitignored)
    out_file = "sentrium_users_generated.json"
    with open(out_file, "w") as f:
        json.dump(users, f, indent=2)
    print(f"  Also saved to {out_file}  (gitignored — never commit this file)\n")

if __name__ == "__main__":
    main()
