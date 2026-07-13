# Handoff

## What we built

A single-file Python CLI (`parser.py`, stdlib only) that extracts key fields
from Sysmon Event ID 1 (Process Creation) XML events and prints them as
JSON, with CLI filtering.

Fields extracted: `EventID`, `UtcTime`, `Image`, `CommandLine`, `User`,
`IntegrityLevel`, `ParentImage`, `ParentCommandLine`, `Computer`, `Hashes`.

Sample events live in `samples/` (`event1.xml`, `event2.xml`, `event3.xml`,
`multi_events.xml`).

## How to use it

```
python parser.py <path-to-sysmon-xml>
```

Handles both a single top-level `<Event>` file and an `<Events>`-wrapped
file with multiple events. Output is a single JSON object for one
(matching) event, or a JSON array otherwise (`[]` if nothing matches).

Filter with any combination of:

```
python parser.py samples/multi_events.xml --image-contains powershell
python parser.py samples/multi_events.xml --user "CORP\jdoe"
python parser.py samples/multi_events.xml --integrity Medium
python parser.py samples/multi_events.xml --integrity High --integrity Low
```

- `--image-contains` — case-insensitive substring match against `Image`.
- `--user` — exact match against `User`.
- `--integrity` — exact match against `IntegrityLevel`, repeatable
  (OR'd together), restricted to `High`/`Medium`/`Low`/`System`.
- All filters combine with AND logic; all are optional.

(On this Windows shell, `python` isn't aliased — use `py parser.py ...`.)

## What's left to do

- **No error handling for missing files or invalid XML.** A bad path or
  malformed file currently surfaces as a raw Python traceback
  (`FileNotFoundError` / `xml.etree.ElementTree.ParseError`), not a clean
  CLI error message.
- **No streaming support.** `parse_file` loads the whole XML file into
  memory via `ET.parse`. Fine at current sample sizes; a large multi-event
  file would need an `iterparse`-based rewrite. Flagged during the session
  but not implemented or even commented in the code yet.
- **No `--command-contains` filter.** Discussed as a natural extension
  (matching `CommandLine` for things like `"encoded"` or `"-enc"`, likely
  repeatable/OR'd like `--integrity`) but not built.
- **No automated tests.** All verification so far has been manual CLI runs
  against the sample files.

## Decisions made and why

- **Stdlib only** (`argparse`, `json`, `xml.etree.ElementTree`) — no
  dependency manifest exists or is needed for a script this size.
- **`parse_file` always returns a list; collapsing to a single object
  happens separately in `format_output`, after filtering.** This makes the
  single-object-vs-array output rule apply to filtered results (a filename
  with many events but only one filter match should print an object,
  and zero matches should print `[]`), rather than being decided purely by
  how many events were in the source file.
- **`--image-contains` is case-insensitive**; Windows paths are
  case-insensitive at the filesystem level, and exact-case matching would
  be a UX footgun for process-name searching.
- **`--user` is an exact, case-sensitive match** — kept simple/predictable
  rather than guessing at case-insensitive domain\username semantics.
- **`--integrity` is repeatable and OR's its values**, restricted via
  argparse `choices=`. An event only has one `IntegrityLevel`, so "match
  any of the given values" is the only sensible semantics for allowing
  more than one; `choices=` gives free validation and a clear error on
  typos instead of silently matching nothing.
- **Filters combine with AND** across the three flags (not just within
  `--integrity`), so e.g. `--image-contains powershell --integrity Medium`
  narrows on both conditions at once.
