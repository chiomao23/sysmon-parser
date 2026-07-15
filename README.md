sysmon-parser

A lightweight Python command-line tool for parsing Sysmon Event ID 1 (process creation) XML logs. It extracts commonly used process information and supports filtering, summary statistics, and multiple export formats for security analysis.

Features:

Parses Sysmon Event ID 1 logs from XML files
Supports filtering by common process attributes
Outputs data in JSON, JSONL, or CSV
Includes a statistics mode for quick log summaries
Uses only Python's standard library

Limitations:

Not optimized for very large XML files
No automated test suite
Sample data is synthetic
