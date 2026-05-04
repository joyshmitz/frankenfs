# Open-Ended Note Scanner Positive Fixture

This fixture is consumed by `open_ended_note_scanner_fixture_docs_emit_expected_rows`.
Every match below is annotated with a bead id or artifact path so the scanner
classifies each row into a closed lane (no unresolved notes).

## Real notes that are already linked

- expand corpus is tracked by bd-l7ov7 with artifact tests/open-ended-inventory/expand_corpus.json
- TODO fuzz is tracked by bd-l7ov7 with artifact tests/open-ended-inventory/todo_fuzz.json
- more goldens is tracked by bd-l7ov7 with artifact tests/open-ended-inventory/more_goldens.json
- known gaps is tracked by bd-l7ov7 with artifact tests/open-ended-inventory/known_gaps.json

## False positives — quoted examples

> add more cases for the parser is shown here as a quoted example only.

```
adversarial inputs in this code block are illustrative, not actionable.
```

## False positive — historical closed context

Historical context: closed bead bd-l7ov7 originally asked to expand corpus before
this scanner existed; the request is fully tracked.
