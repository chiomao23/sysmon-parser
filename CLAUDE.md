# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A single-file Python tool (`parser.py`) that extracts key fields from Sysmon Event ID 1 (Process Creation) XML events and prints them as JSON. No external dependencies — uses only the standard library (`xml.etree.ElementTree` for parsing, `argparse` for the CLI and filter flags, `json` for output).

## Commands

Run the parser against a sample event:

```
python parser.py samples/event1.xml
```

Run against a file containing multiple events (wrapped in `<Events>`):

```
python parser.py samples/multi_events.xml
```

Filter results with `--image-contains`, `--user`, and/or `--integrity` (repeatable). Flags are optional and combine with AND logic:

```
python parser.py samples/multi_events.xml --image-contains powershell --integrity Medium
python parser.py samples/multi_events.xml --integrity High --integrity Low
```

There is no build step, package manifest, linter config, or test suite in this repo.

## Architecture

- `parse_event(event_elem)` — pulls `EventID` and `Computer` from `<System>`, then builds a `Name`→text map from every `<Data>` element under `<EventData>` and looks up the fields listed in `FIELDS` by name. Fields not present in the XML come back as `None`.
- `parse_file(path)` — parses the XML tree and normalizes the two supported input shapes: a root `<Events>` element containing multiple `<Event>` children, or a single top-level `<Event>`. Always returns a `list[dict]` (no collapsing) — collapsing happens later in `format_output`.
- `matches_filters(event, image_contains=None, user=None, integrity_levels=None)` — pure predicate combining the three CLI filters with AND logic. `image_contains` is a case-insensitive substring match against `Image`; `user` is an exact match against `User`; `integrity_levels` is a list (from the repeatable `--integrity` flag) matched with OR semantics against `IntegrityLevel`, since an event only has one integrity level.
- `format_output(events)` — collapses a list to a single dict when there's exactly one event, otherwise leaves it as a list. Applied after filtering, so a filtered-to-zero result prints `[]` and a filtered-to-one result prints a single object.
- All XML lookups use the namespaced tag `e:` bound to `http://schemas.microsoft.com/win/2004/08/events/event` (the `NS` dict) — Sysmon XML is namespaced, so any new `find`/`findall`/`findtext` call must pass `NS`.

The field extraction is driven by two things that must stay in sync with each other and with the fields listed in this file's original spec below:
- `FIELDS` in `parser.py` (the `<Data Name="...">` keys pulled from `EventData`)
- the `EventID`/`Computer` handling in `parse_event`, which comes from `<System>` rather than `<Data>`

## Fields extracted

- EventID
- UtcTime
- Image (process path)
- CommandLine
- User
- IntegrityLevel
- ParentImage
- ParentCommandLine
- Computer
- Hashes

## Output format

JSON — one object per event, or a JSON array when parsing multiple events. This collapse is evaluated after filters are applied: a single matching event prints as an object, zero matches print `[]`.
