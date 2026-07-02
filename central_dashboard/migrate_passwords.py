"""
Sentrium — One-Time Password Migration Script
=============================================
Migrates plain-text passwords in PostgreSQL to bcrypt hashes.
Safe to run multiple times — already-hashed passwords are skipped.

Run once on Railway console after deploying the VAPT security fixes:
    python migrate_passwords.py

Or locally with DATABASE_URL set:
    DATABASE_URL=postgresql://... python migrate_passwords.py
"""
import os
import sys
import logging

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("migrate_passwords")


def migrate():
    db_url = os.environ.get("DATABASE_URL", "")
    if not db_url:
        logger.error("DATABASE_URL is not set. Cannot migrate.")
        sys.exit(1)

    # Normalize Railway postgres:// → postgresql://
    if db_url.startswith("postgres://"):
        db_url = "postgresql://" + db_url[len("postgres://"):]

    try:
        import bcrypt
    except ImportError:
        logger.error("bcrypt not installed. Run: pip install bcrypt")
        sys.exit(1)

    try:
        import psycopg2
        import psycopg2.extras
    except ImportError:
        logger.error("psycopg2 not installed.")
        sys.exit(1)

    # Try SSL first, then without
    conn = None
    for ssl_opts in [{"sslmode": "require"}, {"sslmode": "disable"}, {}]:
        try:
            conn = psycopg2.connect(db_url, cursor_factory=psycopg2.extras.RealDictCursor, **ssl_opts)
            logger.info(f"Connected to PostgreSQL (ssl={ssl_opts})")
            break
        except Exception as e:
            logger.warning(f"Connection attempt failed ({ssl_opts}): {e}")

    if not conn:
        logger.error("Could not connect to PostgreSQL. Check DATABASE_URL.")
        sys.exit(1)

    try:
        with conn.cursor() as cur:
            # Detect password column name
            cur.execute("""
                SELECT column_name FROM information_schema.columns
                WHERE table_name = 'sentrium_users'
                  AND column_name IN ('password', 'password_hash')
                LIMIT 1
            """)
            row = cur.fetchone()
            pw_col = row["column_name"] if row else "password"
            logger.info(f"Password column: '{pw_col}'")

            # Load all users
            cur.execute(f"SELECT email, {pw_col} AS password FROM sentrium_users")
            users = cur.fetchall()
            logger.info(f"Found {len(users)} user(s) to check")

        migrated = 0
        skipped = 0
        errors = 0

        for user in users:
            email = user["email"]
            stored = user["password"] or ""

            # Already bcrypt-hashed → skip
            if stored.startswith("$2b$") or stored.startswith("$2a$"):
                logger.info(f"  SKIP  {email} — already hashed")
                skipped += 1
                continue

            if not stored:
                logger.warning(f"  SKIP  {email} — empty password, cannot migrate")
                skipped += 1
                continue

            # Hash the plain-text password
            try:
                hashed = bcrypt.hashpw(stored.encode(), bcrypt.gensalt(rounds=12)).decode()
                with conn.cursor() as cur:
                    cur.execute(
                        f"UPDATE sentrium_users SET {pw_col} = %s WHERE LOWER(email) = LOWER(%s)",
                        (hashed, email)
                    )
                conn.commit()
                logger.info(f"  HASHED {email}")
                migrated += 1
            except Exception as e:
                conn.rollback()
                logger.error(f"  ERROR  {email}: {e}")
                errors += 1

        logger.info("")
        logger.info("=" * 50)
        logger.info(f"Migration complete: {migrated} hashed, {skipped} skipped, {errors} errors")
        logger.info("=" * 50)

        if errors:
            logger.warning("Some passwords could not be migrated. Check errors above.")
            sys.exit(1)

    finally:
        conn.close()


if __name__ == "__main__":
    migrate()
