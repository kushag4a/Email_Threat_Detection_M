from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.app.services.email_parser import parse_rfc822_bytes
from backend.app.services.attachment_analysis import analyze_attachments


FIXTURE = (
    PROJECT_ROOT
    / "tests"
    / "fixtures"
    / "phishing_eml_suite"
    / "03_invoice_attachment.eml"
)


def main():
    raw = FIXTURE.read_bytes()

    email = parse_rfc822_bytes(
        raw,
        provider="fixture",
        message_id="invoice-attachment-test",
    )

    print("=" * 90)
    print("ATTACHMENT / YARA DIAGNOSTIC")
    print("=" * 90)

    print(f"Fixture: {FIXTURE.name}")
    print(f"Attachments parsed: {len(email.attachments)}")

    result = analyze_attachments(
        [a.model_dump() for a in email.attachments]
    )

    print(f"\nOverall scanned: {result['scanned']}")
    print(f"High severity:   {result['has_high_severity']}")
    print(
        f"High severity files: "
        f"{result['high_severity_filenames']}"
    )

    for item in result["items"]:
        print("\n" + "-" * 90)
        print(f"Filename:       {item['filename']}")
        print(f"Declared type:  {item['declared_type']}")
        print(f"Detected type:  {item['detected_type']}")
        print(f"Extension:      {item['extension']}")
        print(f"Category:       {item['category']}")
        print(f"Flags:          {item['flags']}")

        yara = item["yara"]

        print(f"YARA scanned:   {yara['scanned']}")
        print(f"YARA reason:    {yara['reason']}")
        print(f"YARA matches:   {yara['matches']}")

    print("\n" + "=" * 90)


if __name__ == "__main__":
    main()