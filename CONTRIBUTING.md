# Contributing to siglint

Thanks for taking a look. The most useful contribution is usually **a new
detection rule** — they're small, self-contained, and don't require touching
the engine.

## Dev setup

```bash
git clone https://github.com/a0merr/siglint
cd siglint
pip install -e ".[dev]"
pytest -q
```

## Writing a rule

Rules live in `rules/` as one YAML file each. Minimal shape:

```yaml
title: Human-readable name
id: snake_case_id          # stable, unique — used as the SARIF ruleId
level: low|medium|high|critical
description: One line on what this catches and why it matters.
logsource: auth            # free-form hint (auth, web, process, windows-security…)
detection:
  selection:
    <field>|<modifier>: <value or [list of values]>
  filter:                  # optional: any number of named searches
    <field>: <value>
  threshold:               # optional
    count: 5
    group_by: src_ip
  condition: selection and not filter
```

### Fields

Each event is a flat dict. The parser always provides `raw` (the whole line)
and, where it can, `message`, `src_ip`, `user`. JSON logs expose their own keys
directly. Windows event JSON is normalized to `event_id`, `provider`, `message`.

Match on `raw` when you're not sure a field exists — it's always present.

### Searches, conditions, modifiers

siglint follows Sigma's detection syntax — the README's
[Writing a rule](README.md#writing-a-rule) section has the full modifier table.
In short:

- Multiple fields in a search mean **AND**; a list of values means **OR**
  (add `|all` to require every value).
- Matching is case-insensitive; `*` / `?` are wildcards.
- `condition` combines searches with `and`, `or`, `not`, parentheses and
  `1 of selection_*` / `all of them`.

Run `siglint validate rules` before opening a PR — it catches unknown
modifiers, bad regexes, conditions that reference missing searches, and
duplicate ids.

### Thresholds

Add a `threshold` to fire only after `count` matches, optionally bucketed by
`group_by` (e.g. 5 failed logins **per `src_ip`**). Without `group_by`, all
matches fall in one bucket.

### Test your rule

Add a line that should trigger it to the right file in `examples/`, then assert
it fires in `tests/test_engine.py`. Run `pytest -q`. A rule without a test won't
be merged.

## Pull requests

- One rule (or one focused change) per PR.
- Keep `id` values stable — they're the SARIF `ruleId` downstream tools key on.
- CI must be green: `pytest` on 3.10–3.13, `siglint validate rules`, and the sample-log scan.

## Reporting false positives

Open an issue with the rule `id` and a log line it wrongly flagged (redact
anything sensitive). Tightening a noisy rule is a great first contribution.
