# DocForensics

Read-only document tamper-trace scanner for **PDF, JPEG, PNG and OOXML (docx/xlsx/pptx)**,
plus a **blind, certificate-bound benchmark harness** (`docforensics-fixtures`).

The scanner only ever sees the file it is given. Benchmark ground truth lives in an
**external JSON certificate** that is never embedded in, appended to, or passed alongside
the artifact. Every state the scanner reports is worded so that *absence of evidence is
never converted into proof of authenticity*.

```
pip install -e .          # pikepdf + Pillow
docforensics scan FILE                     # human summary (Arabic + English explanation)
docforensics scan FILE --json -            # machine-readable
docforensics scan FILE --html report.html
```

## Production scanner

* **Universal intake** — any file, any extension. Format is identified content-first
  (magic bytes, container inspection, parser validation); the suffix is only recorded as a
  hint. Unknown binaries get safe generic characteristics and an `unsupported_format`
  limit; partially readable files return findings plus `analysis_limits`. The input is
  opened once, read-only: `SHA-256(before) == SHA-256(after)` is enforced by tests.
* **Findings** separate raw `evidence` from `interpretation`, carry a `severity`
  (`info|weak|moderate|strong`), a `confidence`, and an `is_trace` flag. Informational
  observations (a Software tag exists, a PDF has one revision) never flip the status.
* **`tamper_status.state`**
  * `traces_found` — at least one trace rule fired;
  * `no_traces_found` — inspectable history existed, no supported trace was identified
    (*not* a claim the file was never modified);
  * `no_history_available` — not enough inspectable history to decide either way
    (*never* proof of authenticity).
  Each state ships an Arabic and an English explanation.

### Rule families

| family | rules |
|---|---|
| `pdf.tamper` | `incremental_revisions`, `recovered_prior_metadata`, `docinfo_xmp_divergence` (dates normalised to UTC), `xmp_identity_anomaly`, `structural_fingerprint_conflict`, `file_id_anomaly`, `date_dialect_conflict` |
| `image.tamper` | `exif_thumbnail_mismatch` (aspect + content vs full image), `makernote_integrity`, `datetime_inconsistency`, `encoding_profile_conflict`, `png_chunk_profile_conflict`, `png_chunk_integrity`, `software_editor_tag` (info) |
| `ooxml.tamper` | `core_dates_anomaly`, `entry_timestamp_vs_core_modified`, `package_profile_conflict`, `revision_counter_anomaly`, `relationship_inconsistency`, `last_modified_by_anomaly`, `zip_comment_present` (info) |

PDF revisions are recovered per PDF 32000-1 §7.5.6 by truncating at each earlier `%%EOF`
and re-opening the prefix with pikepdf, so superseded `/Info`, XMP and `/ID` values are
reported as direct evidence with their byte range.

### Empirical generator profiles

`structural_fingerprint_conflict`, `encoding_profile_conflict`, `png_chunk_profile_conflict`,
`package_profile_conflict` and the profile-based checks in `file_id_anomaly` /
`date_dialect_conflict` compare metadata-independent features against
`src/docforensics/profiles/generators.json`. Nothing there is hand-written: it is measured
with `docforensics-fixtures learn-profiles` from a controlled reference corpus. A generator
with few samples yields low confidence (`n<2 → 0.15`, `n≥5 → 0.6`, `n≥20 → 0.9`); an
unknown generator yields no finding at all.

## Blind benchmark (`docforensics-fixtures`)

```
docforensics-fixtures --root ./bench build --trace-class all --seed 1337
docforensics-fixtures --root ./bench list
docforensics-fixtures --root ./bench export CASE --artifact-out ./sample_4f91c2.pdf --certificate-out ./sample_4f91c2.certificate.json
docforensics-fixtures --root ./bench export-artifact CASE --out ./sample_4f91c2.pdf
docforensics-fixtures --root ./bench export-certificate CASE --out ./sample_4f91c2.certificate.json
docforensics-fixtures verify-certificate --artifact ./sample_4f91c2.pdf --certificate ./sample_4f91c2.certificate.json
docforensics-fixtures --root ./bench evaluate --json report.json
docforensics-fixtures --root ./bench record-external CASE --name DetectorB --version 1.0 --result no_traces_found --artifact-sha256 <sha>
```

* **Two independent downloads.** The artifact is a standalone native file; the certificate
  is a standalone UTF-8 JSON file. No zip, tar, bundle or folder export exists; export
  refuses archive suffixes and directories. `sample_<token>.<ext>` and
  `sample_<token>.certificate.json` share only an opaque pairing token.
* **Zero disclosure.** No artifact contains harness words (SYNTHETIC, TAMPERED, GROUND
  TRUTH, …, or Arabic equivalents), case ids, hashes, operation ids or certificate paths in
  any inspectable surface (raw bytes, decompressed PDF streams, DocInfo/XMP, EXIF, PNG
  chunks, ZIP members/names/comments/extra fields). The builder refuses to save a case that
  fails this check.
* **Cryptographic binding.** `artifact.final_sha256` and `original.sha256` bind the
  certificate to exact bytes; `integrity.digest` covers the certificate body, so swapped
  certificates, a one-byte change in the artifact, or an edited field all fail verification.
* **Two test classes.** `natural_trace` cases are ordinary operations that genuinely leave
  residue (incremental PDF saves, EXIF-preserving re-encodes, generic re-zips, in-place tag
  rewrites); `expect_rules` is declared a priori from the operation's mechanics.
  `trace_neutral` cases regenerate the document through the *same* writer from an edited
  content spec — if that still leaves residue the case is reclassified, never doctored.
  Unmodified controls are built alongside.
* **Scanner isolation.** Evaluation copies each artifact under a random neutral name into a
  scratch workspace, runs `docforensics` in a subprocess with a scrubbed environment and a
  Python audit hook that logs every `open`, and only then loads the certificate. Any access
  under the fixture root fails the run.
* **Metrics are never combined:** `natural_trace_detection_rate`,
  `clean_false_positive_rate`, `observable_trace_false_negative_rate`,
  `trace_neutral_provenance_limit_rate`. External detectors are recorded per case beside the
  artifact only when they hashed the exact certified bytes (same-byte rule).
* **Safety.** Transformations accept ephemeral capability handles from the current run's
  registry, never arbitrary paths; `..`, symlink escapes and outputs outside the root are
  rejected. The harness is not a general-purpose provenance-concealment tool.

## Tests

```
pytest -q
```

## Limitations (stated, not hidden)

* Generator profiles ship for the controlled corpus's fictitious writers plus `pikepdf`;
  real-world producers need a reference corpus of your own (`learn-profiles --out`).
* A full rewrite by the original writer leaves nothing to find; the scanner says so
  (`no_traces_found` / evidence limit) instead of guessing.
