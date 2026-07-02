#!/usr/bin/env python3
"""
Sentrium Enterprise — User Management CLI
==========================================
Manage users directly in Railway PostgreSQL.

Usage (from Railway dashboard → service → "Railway CLI"):
    railway run python manage_users.py

Or locally (with DATABASE_URL set):
    $env:DATABASE_URL="postgresql://..." ; python manage_users.py
"""
import os
import sys
import json
import getpass
import re

# Ensure project root is in path
sys.path.insert(0, os.path.dirname(__file__))

try:
    import bcrypt
except ImportError:
    print("ERROR: bcrypt not installed. Run: pip install bcrypt")
    sys.exit(1)

try:
    import db_users
    db_users.init_db()
except Exception as e:
    print(f"ERROR: Could not connect to database: {e}")
    print("Make sure DATABASE_URL is set.")
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

def is_valid_email(email: str) -> bool:
    return bool(re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', email.strip()))

def hash_password(pw: str) -> str:
    return bcrypt.hashpw(pw.encode(), bcrypt.gensalt(rounds=12)).decode()

def pick_department() -> str:
    print("\n  Departments:")
    for i, d in enumerate(DEPARTMENTS, 1):
        print(f"    {i:>2}. {d}")
    while True:
        c = input("  Select number: ").strip()
        if c.isdigit() and 1 <= int(c) <= len(DEPARTMENTS):
            return DEPARTMENTS[int(c) - 1]
        print("  Invalid. Enter a number.")

def pick_role() -> str:
    while True:
        r = input("  Role [1=staff  2=admin] (default 1): ").strip()
        if r in ("", "1"): return "dept_user"
        if r == "2": return "admin"
        print("  Enter 1 or 2.")

def get_password(label="Password (min 10 chars)") -> str:
    while True:
        pw  = getpass.getpass(f"  {label}: ")
        pw2 = getpass.getpass("  Confirm password    : ")
        if not pw: print("  Password cannot be empty."); continue
        if len(pw) < 10: print("  Minimum 10 characters."); continue
        if pw != pw2: print("  Passwords do not match."); continue
        return pw

# ── Actions ──────────────────────────────────────────────────────────────────
def cmd_list():
    users = db_users.list_users()
    if not users:
        print("  No users found.")
        return
    print(f"\n  {'EMAIL':<35} {'DEPARTMENT':<25} {'ROLE':<12} {'ACTIVE'}")
    print("  " + "-"*85)
    for u in users:
        active = "✓" if u["is_active"] else "✗"
        print(f"  {u['email']:<35} {u['department']:<25} {u['role']:<12} {active}")
    print(f"\n  Total: {len(users)} user(s)\n")

def cmd_add():
    print("\n  ── Add New User ────────────────────────")
    while True:
        email = input("  Email address: ").strip().lower()
        if not is_valid_email(email):
            print("  Invalid email format."); continue
        existing = db_users.get_user(email)
        if existing:
            print(f"  {email} already exists. Use 'update' to change their details.")
            return
        break

    dept = pick_department()
    role = pick_role()
    pw   = get_password()
    ok, err = db_users.add_user(email, hash_password(pw), dept, role)
    if ok:
        print(f"\n  ✓ {email} ({dept}, {role}) added successfully.\n")
    else:
        print(f"\n  ✗ Failed: {err}\n")

def cmd_update():
    print("\n  ── Update User ─────────────────────────")
    email = input("  Email to update: ").strip().lower()
    user  = db_users.get_user(email)
    if not user:
        print(f"  User {email} not found."); return

    print(f"\n  Current: {user['department']} | {user['role']} | active={user['is_active']}")
    print("  What to update?")
    print("    1. Password")
    print("    2. Department")
    print("    3. Role")
    print("    4. Deactivate / Reactivate")
    print("    5. Cancel")

    choice = input("  Select: ").strip()
    if choice == "1":
        pw = get_password("New password (min 10 chars)")
        ok = db_users.update_password(email, hash_password(pw))
        print(f"  {'✓ Password updated.' if ok else '✗ Failed.'}")
    elif choice == "2":
        dept = pick_department()
        ok = db_users.update_user(email, department=dept)
        print(f"  {'✓ Department updated to ' + dept if ok else '✗ Failed.'}")
    elif choice == "3":
        role = pick_role()
        ok = db_users.update_user(email, role=role)
        print(f"  {'✓ Role updated to ' + role if ok else '✗ Failed.'}")
    elif choice == "4":
        current_active = user.get("is_active", True)
        action = "Reactivate" if not current_active else "Deactivate"
        confirm = input(f"  {action} {email}? [y/N]: ").strip().lower()
        if confirm == "y":
            ok = db_users.update_user(email, is_active=not current_active)
            print(f"  {'✓ ' + action + 'd.' if ok else '✗ Failed.'}")
    else:
        print("  Cancelled.")

def cmd_delete():
    print("\n  ── Delete User ─────────────────────────")
    email = input("  Email to delete: ").strip().lower()
    if not db_users.get_user(email):
        print(f"  User {email} not found."); return
    confirm = input(f"  Permanently delete {email}? Type email to confirm: ").strip().lower()
    if confirm == email:
        ok = db_users.delete_user(email)
        print(f"  {'✓ Deleted.' if ok else '✗ Failed.'}")
    else:
        print("  Cancelled — email did not match.")

def cmd_import():
    """Import users from sentrium_users_generated.json into PostgreSQL."""
    path = input("  Path to JSON file [sentrium_users_generated.json]: ").strip()
    if not path:
        path = "sentrium_users_generated.json"
    try:
        with open(path) as f:
            data = json.load(f)
        inserted, skipped = db_users.import_from_json(data)
        print(f"\n  ✓ Import complete: {inserted} inserted, {skipped} skipped (already exist).\n")
    except FileNotFoundError:
        print(f"  File not found: {path}")
    except Exception as e:
        print(f"  Error: {e}")

# ── Main menu ────────────────────────────────────────────────────────────────
def main():
    print("\n" + "="*55)
    print("  Sentrium Enterprise — User Management")
    print(f"  Database: {os.environ.get('DATABASE_URL','(not set)')[:40]}...")
    print("="*55)

    # Show user count on startup
    users = db_users.list_users()
    print(f"  {len(users)} user(s) currently in database.\n")

    MENU = {
        "1": ("List all users",         cmd_list),
        "2": ("Add new user",           cmd_add),
        "3": ("Update user",            cmd_update),
        "4": ("Delete user",            cmd_delete),
        "5": ("Import from JSON file",  cmd_import),
        "6": ("Exit",                   None),
    }

    while True:
        print("\n  What would you like to do?")
        for k, (label, _) in MENU.items():
            print(f"    {k}. {label}")
        choice = input("\n  Select: ").strip()
        if choice == "6":
            print("  Goodbye.\n"); break
        if choice in MENU and MENU[choice][1]:
            MENU[choice][1]()
        else:
            print("  Invalid choice.")

if __name__ == "__main__":
    main()
