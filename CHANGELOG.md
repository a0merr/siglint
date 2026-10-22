# Changelog

## 0.3.0

- **`timeframe`:** threshold rules can require their matches to fall inside a
  sliding window (`30s`, `5m`, `1h`, `1d`). Findings report the densest window
  and its span — in the table, JSON (`span_seconds`), and SARIF message.
- **Event times:** parsed from syslog, ISO-8601 JSON keys, PowerShell
  `/Date(ms)/`, epoch seconds/ms, and access-log brackets. Year-less syslog
  borrows the file's year and survives a December → January rollover.
- `ssh_brute_force` now means 5 failures within 1m; `windows_failed_logon`
  3 within 5m.

## 0.2.0

Real Sigma detection syntax — 3,136 of 3,161 SigmaHQ rules now load.

- **Conditions:** `and` / `or` / `not`, parentheses, `1 of selection_*`,
  `all of filter_*`, `1 of them`, and lists of conditions.
- **Searches:** any number of named searches per rule; lists of maps (OR) and
  keyword lists over the raw line.
- **Matching:** case-insensitive by default with `*` / `?` wildcards; `null`
  matches a missing or empty field.
- **Modifiers:** `all`, `re` (+ `i` `m` `s`), `windash`, `cidr`,
  `gt` / `gte` / `lt` / `lte`, `cased`.
- **`siglint validate`:** lints a rule tree in one pass — unknown modifiers,
  bad regexes, dangling condition references, duplicate ids.
- **`siglint scan`** takes several log files; thresholds count across all of
  them. Bad rules exit 2 with a pointer to `validate` instead of a traceback.
- New rules: `uid0_account_created`, `log_tampering`; `sudo_auth_failure`
  now filters CI service accounts.

## 0.1.0

First release: syslog/JSON/Windows-event parsing, single-selection rules with
thresholds, table/JSON/SARIF output, `--fail-on` gating.
