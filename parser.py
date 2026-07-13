#!/usr/bin/env python3
import argparse
import csv
import json
import sys
import xml.etree.ElementTree as ET

NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}

FIELDS = [
    "UtcTime",
    "Image",
    "CommandLine",
    "User",
    "IntegrityLevel",
    "ParentImage",
    "ParentCommandLine",
    "Hashes",
]

CSV_FIELDS = ["EventID", "Computer"] + FIELDS


def parse_event(event_elem):
    result = {}

    system = event_elem.find("e:System", NS)
    result["EventID"] = system.findtext("e:EventID", namespaces=NS)
    result["Computer"] = system.findtext("e:Computer", namespaces=NS)

    event_data = event_elem.find("e:EventData", NS)
    data_by_name = {
        data.get("Name"): (data.text or "")
        for data in event_data.findall("e:Data", NS)
    }
    for field in FIELDS:
        result[field] = data_by_name.get(field)

    return result


def parse_file(path):
    tree = ET.parse(path)
    root = tree.getroot()

    if root.tag.endswith("Events"):
        events = root.findall("e:Event", NS)
    else:
        events = [root]

    return [parse_event(event) for event in events]


def matches_filters(event, image_contains=None, user=None, integrity_levels=None):
    if image_contains is not None:
        image = event.get("Image")
        if image is None or image_contains.lower() not in image.lower():
            return False

    if user is not None and event.get("User") != user:
        return False

    if integrity_levels and event.get("IntegrityLevel") not in integrity_levels:
        return False

    return True


def format_output(events):
    return events[0] if len(events) == 1 else events


def print_json(events):
    print(json.dumps(format_output(events), indent=2))


def print_jsonl(events):
    for event in events:
        print(json.dumps(event))


def print_csv(events):
    writer = csv.DictWriter(sys.stdout, fieldnames=CSV_FIELDS, lineterminator="\n")
    writer.writeheader()
    writer.writerows(events)


PRINTERS = {
    "json": print_json,
    "jsonl": print_jsonl,
    "csv": print_csv,
}


# This stats feature is for quick triage to understand what's in a file before deep analysis
def compute_stats(events):
    integrity_counts = {}
    for event in events:
        level = event.get("IntegrityLevel")
        integrity_counts[level] = integrity_counts.get(level, 0) + 1

    return {
        "total_events": len(events),
        "unique_images": len({e["Image"] for e in events if e.get("Image") is not None}),
        "unique_users": len({e["User"] for e in events if e.get("User") is not None}),
        "events_by_integrity_level": integrity_counts,
    }


def main():
    parser = argparse.ArgumentParser(
        description="Extract key fields from Sysmon Event ID 1 (Process Creation) XML"
    )
    parser.add_argument("path", help="Path to a Sysmon XML file")
    parser.add_argument(
        "--image-contains", help="Keep events where Image contains this substring (case-insensitive)"
    )
    parser.add_argument("--user", help="Keep events where User exactly matches this value")
    parser.add_argument(
        "--integrity",
        action="append",
        choices=["High", "Medium", "Low", "System"],
        help="Keep events where IntegrityLevel matches. Repeatable to match any of several levels.",
    )
    parser.add_argument(
        "--format",
        choices=["json", "jsonl", "csv"],
        default="json",
        help="Output format: json (array/object, default), jsonl (one JSON object per line), or csv",
    )
    parser.add_argument(
        "--stats",
        action="store_true",
        help="Print summary statistics (total events, unique images/users, counts by IntegrityLevel) instead of event records",
    )
    args = parser.parse_args()

    events = parse_file(args.path)
    filtered = [
        e
        for e in events
        if matches_filters(
            e,
            image_contains=args.image_contains,
            user=args.user,
            integrity_levels=args.integrity,
        )
    ]

    if args.stats:
        print(json.dumps(compute_stats(filtered), indent=2))
        return

    PRINTERS[args.format](filtered)


if __name__ == "__main__":
    main()
