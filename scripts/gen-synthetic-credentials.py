#!/usr/bin/env python3
"""Write synthetic, credential-shaped lab data for Defender sensitive data discovery.

Every value is random and generated at upload time, so nothing secret-shaped is ever
committed (gitleaks and GitHub push protection stay quiet). The values have the shape
of real credentials on purpose: Purview's credential SITs skip anything that looks like
a placeholder or an example, so "xxxx" or "example" values are never classified.

None of the keys, accounts or hosts exist. Usage: gen-synthetic-credentials.py <out-dir>
"""

from __future__ import annotations

import base64
import csv
import json
import random
import secrets
import string
import sys
from pathlib import Path
from urllib.parse import quote


def b64(nbytes: int) -> str:
    return base64.b64encode(secrets.token_bytes(nbytes)).decode()


def suffix(n: int = 6) -> str:
    return "".join(secrets.choice(string.ascii_lowercase + string.digits) for _ in range(n))


def password(n: int = 20) -> str:
    alphabet = string.ascii_letters + string.digits + "!#%*+-_"
    while True:
        pw = "".join(secrets.choice(alphabet) for _ in range(n))
        if any(c.isdigit() for c in pw) and any(c.isupper() for c in pw) and any(c in "!#%*+-_" for c in pw):
            return pw


def luhn_card(prefix: str, length: int = 16) -> str:
    digits = [int(d) for d in prefix] + [secrets.randbelow(10) for _ in range(length - len(prefix) - 1)]
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 0:
            d *= 2
            d -= 9 if d > 9 else 0
        total += d
    return "".join(map(str, digits)) + str((10 - total % 10) % 10)


def de_iban() -> str:
    bban = "".join(str(secrets.randbelow(10)) for _ in range(18))
    check = 98 - int(bban + "131400") % 97  # D=13 E=14, then "00"
    return f"DE{check:02d}{bban}"


def storage_conn(account: str) -> str:
    return (f"DefaultEndpointsProtocol=https;AccountName={account};"
            f"AccountKey={b64(64)};EndpointSuffix=core.windows.net")


def storage_sas(account: str) -> str:
    sig = quote(b64(32), safe="")
    return (f"https://{account}.blob.core.windows.net/exports?sv=2022-11-02&ss=bfqt&srt=sco"
            f"&sp=rwdlacupiytfx&se=2027-12-31T23:59:59Z&st=2026-01-01T00:00:00Z&spr=https&sig={sig}")


def build() -> dict:
    env = random.choice(["prod", "prd", "live"])
    sql_server = f"sql-billing-{env}-{suffix()}"
    return {
        "storage": [
            {"name": acct, "connectionString": storage_conn(acct)}
            for acct in (f"st{name}{env}{suffix(4)}" for name in ("billing", "invoices", "backup"))
        ],
        "storageSas": storage_sas(f"stexports{env}{suffix(4)}"),
        "sql": (f"Server=tcp:{sql_server}.database.windows.net,1433;Initial Catalog=billing;"
                f"Persist Security Info=False;User ID=svc_billing;Password={password()};"
                "MultipleActiveResultSets=False;Encrypt=True;TrustServerCertificate=False;"
                "Connection Timeout=30;"),
        "cosmos": (f"AccountEndpoint=https://cosmos-orders-{env}-{suffix()}.documents.azure.com:443/;"
                   f"AccountKey={b64(64)};"),
        "serviceBus": (f"Endpoint=sb://sb-payments-{env}-{suffix()}.servicebus.windows.net/;"
                       f"SharedAccessKeyName=RootManageSharedAccessKey;SharedAccessKey={b64(32)}"),
        "redis": (f"redis-sessions-{env}-{suffix()}.redis.cache.windows.net:6380,"
                  f"password={b64(32)},ssl=True,abortConnect=False"),
        "aws": {
            "aws_access_key_id": "AKIA" + "".join(secrets.choice(string.ascii_uppercase + "234567") for _ in range(16)),
            "aws_secret_access_key": "".join(secrets.choice(string.ascii_letters + string.digits + "/+") for _ in range(40)),
        },
    }


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__.strip().splitlines()[-1], file=sys.stderr)
        return 2
    out = Path(sys.argv[1])
    out.mkdir(parents=True, exist_ok=True)
    c = build()

    # 1) App settings backup (JSON), the kind of file that ends up in a backup container.
    (out / "app-settings-backup.json").write_text(json.dumps({
        "ConnectionStrings": {
            "BillingDb": c["sql"],
            "OrdersCosmos": c["cosmos"],
            "PaymentsBus": c["serviceBus"],
            "SessionCache": c["redis"],
            **{f"Storage_{i}": s["connectionString"] for i, s in enumerate(c["storage"])},
        },
        "ExportSas": c["storageSas"],
    }, indent=2) + "\n")

    # 2) Plain-text config dump (.txt), env-file style.
    lines = [f"AZURE_STORAGE_CONNECTION_STRING={c['storage'][0]['connectionString']}",
             f"SQLCONNSTR_BILLING={c['sql']}",
             f"SERVICEBUS_CONNECTION={c['serviceBus']}",
             f"AWS_ACCESS_KEY_ID={c['aws']['aws_access_key_id']}",
             f"AWS_SECRET_ACCESS_KEY={c['aws']['aws_secret_access_key']}"]
    (out / "deploy-config-dump.txt").write_text("\n".join(lines) + "\n")

    # 3) Customer payment export (CSV): Luhn-valid card numbers and checksum-valid IBANs.
    with (out / "payments-export.csv").open("w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["customer_id", "card_holder", "credit_card_number", "card_type", "expiration_date", "iban"])
        for i, (holder, prefix, kind) in enumerate([
            ("Avery Demo", "4", "Visa"), ("Morgan Sample", "51", "MasterCard"),
            ("Riley Fiction", "4", "Visa"), ("Jordan Mock", "55", "MasterCard"),
            ("Casey Lab", "4", "Visa"),
        ]):
            w.writerow([f"CUST-{1042 + i * 1011}", holder, luhn_card(prefix), kind,
                        f"{secrets.randbelow(12) + 1:02d}/{28 + secrets.randbelow(3)}", de_iban()])

    for f in sorted(out.iterdir()):
        print(f)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
