
#!/usr/bin/env python3

import argparse
import csv
import sys
from pathlib import Path

DEFAULT_DATABASE = Path("threat_indicators.csv")
DEFAULT_OUTPUT = Path("ioc_matches.csv")

IOC_COLUMN_HINTS = (
    "indicator_value",
    "ioc_value",
    "observable_value",
    "indicator",
    "observable",
    "ioc",
    "value",
    "ip_address",
    "ip",
    "domain",
    "hostname",
    "url",
    "md5",
    "sha1",
    "sha256",
    "sha512",
    "hash",
    "pattern",
)

PROVIDER_COLUMN_HINTS = (
    "provider",
    "providers",
    "feed_name",
    "feed",
    "source_name",
    "source",
)


def normalize(value):
    """Normalize IOC values for exact matching."""
    if value is None:
        return ""

    return str(value).strip().strip('"').strip("'").lower()


def find_column(fieldnames, hints):
    """Find likely columns using exact matches first."""
    if not fieldnames:
        return []

    lookup = {
        name.strip().lower(): name
        for name in fieldnames
    }

    for hint in hints:
        if hint in lookup:
            return [lookup[hint]]

    return [
        name for name in fieldnames
        if any(
            hint in name.strip().lower()
            for hint in hints
        )
    ]


def find_ioc_columns(fieldnames):
    """Identify IOC value columns."""
    return find_column(fieldnames, IOC_COLUMN_HINTS)


def find_provider_columns(fieldnames):
    """Identify provider/source columns."""
    return find_column(fieldnames, PROVIDER_COLUMN_HINTS)


def load_indicator_database(path):
    """Load the threat database and build an IOC lookup index."""
    if not path.is_file():
        raise FileNotFoundError(
            f"Threat database not found: {path}"
        )

    index = {}
    total_records = 0

    with path.open(
        "r",
        encoding="utf-8-sig",
        newline="",
    ) as file:
        reader = csv.DictReader(file)

        if not reader.fieldnames:
            raise ValueError(
                f"{path} is empty or has no CSV header."
            )

        fieldnames = reader.fieldnames
        ioc_columns = find_ioc_columns(fieldnames)
        provider_columns = find_provider_columns(fieldnames)

        if not ioc_columns:
            raise ValueError(
                "Could not identify the IOC column.\n"
                f"Available columns: {', '.join(fieldnames)}"
            )

        print(f"[+] Database: {path}")
        print(f"[+] IOC columns: {', '.join(ioc_columns)}")
        print(
            "[+] Provider columns: "
            + (
                ", ".join(provider_columns)
                if provider_columns
                else "None detected"
            )
        )
        print("[+] Loading indicator database...")

        for row_number, row in enumerate(reader, start=2):
            total_records += 1

            for column in ioc_columns:
                value = normalize(row.get(column))

                if value:
                    index.setdefault(value, []).append({
                        "source_row": row_number,
                        "record": row,
                    })

    print(f"[+] Database records: {total_records:,}")
    print(f"[+] Indexed IOC values: {len(index):,}")

    return index, fieldnames, provider_columns


def read_txt(path):
    """Read one IOC per line from a TXT file."""
    with path.open("r", encoding="utf-8-sig") as file:
        return [
            line.strip()
            for line in file
            if line.strip()
            and not line.lstrip().startswith("#")
        ]


def read_csv_iocs(path, column=None):
    """Read IOC values from a CSV file."""
    with path.open(
        "r",
        encoding="utf-8-sig",
        newline="",
    ) as file:
        reader = csv.DictReader(file)

        if not reader.fieldnames:
            raise ValueError(
                f"Input CSV has no header: {path}"
            )

        if column:
            selected = next(
                (
                    name for name in reader.fieldnames
                    if name.strip().lower() == column.strip().lower()
                ),
                None,
            )

            if not selected:
                raise ValueError(
                    f"Column '{column}' not found.\n"
                    f"Available columns: {', '.join(reader.fieldnames)}"
                )
        else:
            candidates = find_ioc_columns(reader.fieldnames)

            if len(candidates) == 1:
                selected = candidates[0]
            elif len(reader.fieldnames) == 1:
                selected = reader.fieldnames[0]
            elif candidates:
                selected = candidates[0]
                print(
                    f"[i] Multiple IOC columns detected. "
                    f"Using '{selected}'. "
                    "Use --column to select another."
                )
            else:
                raise ValueError(
                    "Could not identify the IOC column. "
                    "Specify it using --column."
                )

        values = [
            row.get(selected, "").strip()
            for row in reader
            if row.get(selected, "").strip()
        ]

    print(f"[+] Input IOC column: {selected}")
    return values


def get_iocs(args):
    """Read IOCs from command-line arguments, a file, or manual input."""
    if args.ioc:
        return args.ioc

    if args.input:
        path = Path(args.input)

        if not path.is_file():
            raise FileNotFoundError(
                f"Input file not found: {path}"
            )

        if path.suffix.lower() == ".txt":
            return read_txt(path)

        if path.suffix.lower() == ".csv":
            return read_csv_iocs(path, args.column)

        raise ValueError(
            "Input file must have a .txt or .csv extension."
        )

    print("\nIOC Search")
    print("Enter one IOC per line.")
    print("Press Enter on an empty line to start searching.\n")

    values = []

    while True:
        try:
            value = input("IOC> ").strip()
        except EOFError:
            break

        if not value:
            break

        values.append(value)

    return values


def split_provider_values(value):
    """Split common multi-provider field formats."""
    if not value:
        return []

    text = str(value).strip()

    if not text:
        return []

    # Support common delimiters.
    for delimiter in (";", "|"):
        text = text.replace(delimiter, ",")

    return [
        item.strip()
        for item in text.split(",")
        if item.strip()
    ]


def get_providers(records, provider_columns):
    """Return unique provider names from matching records."""
    providers = []

    for item in records:
        record = item["record"]

        for column in provider_columns:
            value = record.get(column, "")

            for provider in split_provider_values(value):
                if provider not in providers:
                    providers.append(provider)

    return providers


def search_iocs(iocs, index, provider_columns):
    """Search IOCs and display providers after each matched IOC."""
    results = []
    matched = set()
    unmatched = []

    for original_ioc in iocs:
        key = normalize(original_ioc)

        if not key:
            continue

        records = index.get(key, [])

        if not records:
            unmatched.append(original_ioc)
            continue

        matched.add(key)

        providers = get_providers(records, provider_columns)
        provider_text = (
            ", ".join(providers)
            if providers
            else "Unknown provider"
        )

        print(f"  [MATCH] {original_ioc} | {provider_text}")

        for item in records:
            results.append({
                "searched_ioc": original_ioc,
                "database_csv_row": item["source_row"],
                **item["record"],
            })

    return results, matched, unmatched


def write_results(results, output_path, fieldnames):
    """Export matching database records to a separate CSV."""
    if not results:
        print("[-] No matching records to export.")
        return

    output_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    columns = [
        "searched_ioc",
        "database_csv_row",
        *fieldnames,
    ]

    with output_path.open(
        "w",
        encoding="utf-8-sig",
        newline="",
    ) as file:
        writer = csv.DictWriter(
            file,
            fieldnames=columns,
            extrasaction="ignore",
        )
        writer.writeheader()
        writer.writerows(results)

    print(f"[+] Matching records saved to: {output_path}")


def main():
    parser = argparse.ArgumentParser(
        description=(
            "Search IOCs against threat_indicators.csv "
            "and display associated providers."
        )
    )

    parser.add_argument(
        "-i",
        "--ioc",
        action="append",
        help="IOC to search; can be specified multiple times.",
    )

    parser.add_argument(
        "-f",
        "--input",
        help="Input TXT or CSV file containing IOCs.",
    )

    parser.add_argument(
        "--column",
        help="IOC column name in the input CSV.",
    )

    parser.add_argument(
        "-d",
        "--database",
        default=str(DEFAULT_DATABASE),
        help=f"Threat database CSV (default: {DEFAULT_DATABASE})",
    )

    parser.add_argument(
        "-o",
        "--output",
        default=str(DEFAULT_OUTPUT),
        help=f"Output CSV (default: {DEFAULT_OUTPUT})",
    )

    args = parser.parse_args()

    if args.ioc and args.input:
        parser.error("Use --ioc or --input, not both.")

    if args.column and not args.input:
        parser.error("--column can only be used with --input.")

    try:
        index, fieldnames, provider_columns = (
            load_indicator_database(Path(args.database))
        )

        iocs = get_iocs(args)

        # Remove duplicate inputs while preserving their order.
        unique_iocs = list(dict.fromkeys(
            value.strip()
            for value in iocs
            if value.strip()
        ))

        if not unique_iocs:
            print("[-] No IOC values provided.")
            return 1

        print(f"\n[+] IOCs to search: {len(unique_iocs):,}")
        print("\nMATCHED IOCs:")

        results, matched, unmatched = search_iocs(
            unique_iocs,
            index,
            provider_columns,
        )

        print("\n" + "=" * 55)
        print("IOC SEARCH SUMMARY")
        print("=" * 55)
        print(f"Input IOCs:          {len(unique_iocs):,}")
        print(f"Matched unique IOCs: {len(matched):,}")
        print(f"Unmatched IOCs:      {len(unmatched):,}")
        print(f"Matching records:    {len(results):,}")

        if unmatched:
            print("\nUNMATCHED IOCs:")

            for ioc in unmatched:
                print(f"  [NO MATCH] {ioc}")

        write_results(
            results,
            Path(args.output),
            fieldnames,
        )

        return 0

    except (OSError, ValueError, csv.Error) as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
