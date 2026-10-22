# Changelog

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
