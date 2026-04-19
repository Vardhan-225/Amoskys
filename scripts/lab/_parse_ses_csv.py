#!/usr/bin/env python3
"""
_parse_ses_csv.py — helper for inject-ses-creds.sh

Reads an SES SMTP credentials CSV and prints two lines to stdout:
    <SMTP user name>
    <SMTP password>

Rejects legacy IAM access-key CSVs (which cannot be used as SMTP creds).
Does not log the credentials anywhere.
"""
import csv
import sys


def pick(row, *needles):
    for k, v in row.items():
        if k is None:
            continue
        kl = k.lower()
        if all(n in kl for n in needles):
            return v
    return None


def main():
    if len(sys.argv) != 2:
        sys.stderr.write("usage: _parse_ses_csv.py <path-to-csv>\n")
        sys.exit(1)
    path = sys.argv[1]

    # utf-8-sig strips the BOM that AWS sometimes includes in downloaded CSVs
    with open(path, newline="", encoding="utf-8-sig") as f:
        rows = list(csv.DictReader(f))
    if not rows:
        sys.stderr.write("CSV has no data rows\n")
        sys.exit(2)
    row = rows[0]

    # SES SMTP credential CSV column names across AWS revisions:
    #   newer: "SMTP User Name" / "SMTP Password"
    #   older: "User Name" / "Password"
    # Legacy IAM exports use "Access key ID" / "Secret access key" -- NOT valid for SMTP.
    user = pick(row, "smtp", "user") or pick(row, "user", "name") or pick(row, "user")
    pwd = pick(row, "smtp", "password") or pick(row, "password")

    if not user or not pwd:
        legacy_key = pick(row, "access", "key", "id")
        if legacy_key:
            sys.stderr.write(
                "This CSV looks like an IAM access-key export, not an SES SMTP credentials file.\n"
                "SES SMTP requires credentials generated via 'Create SMTP credentials' in the SES console.\n"
                f"Columns seen: {list(row.keys())}\n"
            )
            sys.exit(3)
        sys.stderr.write(
            f"Could not find SMTP user/password columns. Columns seen: {list(row.keys())}\n"
        )
        sys.exit(4)

    user = user.strip()
    pwd = pwd.strip()
    if not user or not pwd:
        sys.stderr.write("SMTP user or password is empty in the CSV\n")
        sys.exit(5)

    # Two lines, no trailing junk, no echoing.
    sys.stdout.write(user + "\n")
    sys.stdout.write(pwd + "\n")


if __name__ == "__main__":
    main()
