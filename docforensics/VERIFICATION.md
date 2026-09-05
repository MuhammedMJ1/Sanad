# Verification evidence (Part L)

Captured from real command runs on 2026-09-05T17:18Z. Paths shortened to `$E` for readability.

## 1. Full test suite
```
$ pytest -q
.................................................                        [100%]
49 passed in 3.21s
```

## 2. Independent export (two standalone files, no archive)
```
$ docforensics-fixtures export cbcf5986ad5 --artifact-out ./sample.pdf --certificate-out ./sample.certificate.json
{
  "artifact": {
    "path": "sample.pdf",
    "sha256": "8cde72109d6611c15891c66ad37eed8bc2376ea5f73ef672ea7b6e745bf45f3d",
    "size_bytes": 2562
  },
  "certificate": {
    "path": "sample.certificate.json",
    "sha256": "bbcfe23ff1897d0317b954206c2dab64666196e199df5509d1c80494fa567b57",
    "size_bytes": 1897
  }
}
$ ls -l
1897 sample.certificate.json
2562 sample.pdf
```

## 3. Hash binding
```
$ sha256sum ./sample.pdf
8cde72109d6611c15891c66ad37eed8bc2376ea5f73ef672ea7b6e745bf45f3d  sample.pdf
$ python -c "import json;print(json.load(open(\"sample.certificate.json\"))[\"artifact\"][\"final_sha256\"])"
8cde72109d6611c15891c66ad37eed8bc2376ea5f73ef672ea7b6e745bf45f3d
$ docforensics-fixtures verify-certificate --artifact ./sample.pdf --certificate ./sample.certificate.json
artifact_hash_match: true
original_hash_match: none
integrity_valid: true
certificate_valid: true
```

## 4. Scan the artifact ALONE (certificate neither passed nor present in the workspace)
```
$ mkdir scan-only && cp sample.pdf scan-only/ && cd scan-only && ls
sample.pdf
$ docforensics scan ./sample.pdf --json - | <print input, tamper_status, trace rule ids>
{
 "input": {
  "path": "sample.pdf",
  "name": "sample.pdf",
  "size_bytes": 2562,
  "sha256": "8cde72109d6611c15891c66ad37eed8bc2376ea5f73ef672ea7b6e745bf45f3d",
  "detected_format": "pdf",
  "format_family": "pdf",
  "format_evidence": "%PDF- header",
  "format_identification": "content-first (magic bytes / container inspection)",
  "extension_hint": ".pdf",
  "extension_agrees_with_content": true,
  "supported": true
 },
 "tamper_status": {
  "state": "traces_found",
  "explanation_ar": "عُثر على مؤشرات فنية قابلة للرصد داخل الملف تتوافق مع حدوث تعديل أو إعادة حفظ. راجع الأدلة التفصيلية لتحديد قوتها.",
  "explanation_en": "Observable technical indicators consistent with post-creation modification or re-saving were found. Review the detailed evidence for their strength.",
  "revisions_found": 2,
  "recovered_prior_metadata": [
   {
    "revision": 0,
    "kind": "docinfo",
    "field": "/Author",
    "old_value": "Hana Nasser",
    "current_value": "Nadia Mansour",
    "source": {
     "revision_index": 0,
     "byte_range": [
      0,
      2176
     ],
     "startxref": 1865
    }
   },
   {
    "revision": 0,
    "kind": "docinfo",
    "field": "/ModDate",
    "old_value": "D:20241011172700+00'00'",
    "current_value": "D:20241119010800Z",
    "source": {
     "revision_index": 0,
     "byte_range": [
      0,
      2176
     ],
     "startxref": 1865
    }
   }
  ],
  "trace_rule_ids": [
   "pdf.tamper.date_dialect_conflict",
   "pdf.tamper.docinfo_xmp_divergence",
   "pdf.tamper.file_id_anomaly",
   "pdf.tamper.incremental_revisions",
   "pdf.tamper.recovered_prior_metadata",
   "pdf.tamper.xmp_identity_anomaly"
  ],
  "proof_of_authenticity": false
 }
}
trace rules: ['pdf.tamper.date_dialect_conflict', 'pdf.tamper.docinfo_xmp_divergence', 'pdf.tamper.file_id_anomaly', 'pdf.tamper.incremental_revisions', 'pdf.tamper.recovered_prior_metadata', 'pdf.tamper.xmp_identity_anomaly']
$ docforensics-fixtures --root bench scan-isolated cbcf5986ad5 --json iso.json   # audit-hooked subprocess: every open() is logged
scanned as: sample_439555.pdf | env keys: ['HOME', 'LANG', 'LC_ALL', 'PATH', 'PYTHONDONTWRITEBYTECODE', 'PYTHONIOENCODING'] | violations: []
opened 111 files; under the bench root: 0; any certificate/original opened: False
non-code files opened: ['generators.json', 'sample_439555.pdf']
```

## 5. test_zero_disclosure
```
$ pytest -q tests/test_zero_disclosure.py
3 passed in 0.29s
```

## 6. test_scanner_isolation
```
$ pytest -q tests/test_scanner_isolation.py
2 passed in 0.56s
```

## 7. test_independent_downloads
```
$ pytest -q tests/test_independent_downloads.py
2 passed in 0.22s
```

## 8. test_certificate_swap
```
$ pytest -q tests/test_certificate_swap.py
2 passed in 0.23s
```

## 9. Clean controls (unmodified reference artifacts)
```
plainpdf     format: pdf  [%PDF- header]  extension hint: .bin tamper_status: no_traces_found 
acme_png     format: png  [PNG 8-byte signature]  extension hint: .bin tamper_status: no_traces_found 
pikepdf      format: pdf  [%PDF- header]  extension hint: .bin tamper_status: no_traces_found 
acme_office  format: docx  [ZIP container with OOXML [Content_Types].xml]  extension hint: .bin tamper_status: no_traces_found 
acme_camera  format: jpeg  [JPEG SOI + marker]  extension hint: .bin tamper_status: no_traces_found 
```

## 10. Natural-trace positives (genuine residue detected) + separated metrics
```
$ docforensics-fixtures evaluate
metrics:
  natural_trace_detection_rate: 1.0  (16/16)
  clean_false_positive_rate: 0.0  (0/5)
  observable_trace_false_negative_rate: 0.0  (0/16)
  trace_neutral_provenance_limit_rate: 1.0  (5/5)
isolation violations: 0
c03644f25fd detected  fired: ooxml.tamper.core_dates_anomaly
c0edfa8c3ea detected  fired: ooxml.tamper.revision_counter_anomaly
c15ed313268 detected  fired: image.tamper.encoding_profile_conflict, image.tamper.exif_thumbnail_mismatch
c1b7b496907 detected  fired: pdf.tamper.incremental_revisions
c21be80c04c detected  fired: image.tamper.png_chunk_profile_conflict
c3919bb9076 detected  fired: pdf.tamper.structural_fingerprint_conflict
c46ef2cee26 detected  fired: image.tamper.datetime_inconsistency
c85662d8037 detected  fired: image.tamper.png_chunk_integrity
c8a25038af1 detected  fired: ooxml.tamper.package_profile_conflict, ooxml.tamper.relationship_inconsistency
ca2e269176c detected  fired: ooxml.tamper.last_modified_by_anomaly
ca3702b6206 detected  fired: image.tamper.encoding_profile_conflict, image.tamper.exif_thumbnail_mismatch
cbcf5986ad5 detected  fired: pdf.tamper.date_dialect_conflict, pdf.tamper.docinfo_xmp_divergence, pdf.tamper.file_id_anomaly, pdf.tamper.incremental_revisions, pdf.tamper.recovered_prior_metadata, pdf.tamper.xmp_identity_anomaly
cc822803d81 detected  fired: pdf.tamper.incremental_revisions, pdf.tamper.recovered_prior_metadata
cd5548debd9 detected  fired: image.tamper.encoding_profile_conflict, image.tamper.makernote_integrity
cdd62889002 detected  fired: ooxml.tamper.entry_timestamp_vs_core_modified, ooxml.tamper.package_profile_conflict
cf86315dbf3 detected  fired: pdf.tamper.file_id_anomaly, pdf.tamper.incremental_revisions
```

## 11. Trace-neutral controlled case
```
original sha256 (certificate): db4dcfb6647d6202b1747038f15ecd37850c014645d325cc303712e0f91a5a10
final sha256    (certificate): ec85012fb38cf3a47e58c6ffb1e76c6f7ba86525a7af6ea9468e9288037bbbce
final sha256    (download)   : ec85012fb38cf3a47e58c6ffb1e76c6f7ba86525a7af6ea9468e9288037bbbce
semantic delta: {'description': 'line item 2 and total changed 3,403.00 -> 4,070.00', 'kind': 'text_content'}
trace_class: trace_neutral | expected_limit: provenance_not_establishable_from_file_alone
harness disclosures inside artifact: []
$ docforensics scan neutral.pdf   (certificate not supplied)
tamper_status: no_traces_found
  لم يعثر التحليل على آثار تعديل ضمن الأدلة التي أمكن فحصها. هذه النتيجة لا تثبت أن الملف لم يُعدّل سابقاً.
  No supported tamper trace was identified in the evidence that could be inspected. This does not prove the file was never modified.
```

## 12. Universal intake
```
noext            format=pdf ext_hint=None status=traces_found limits=[]
photo.jpg        format=pdf ext_hint=.jpg status=traces_found limits=[]
image.bin        format=jpeg ext_hint=.bin status=no_traces_found limits=[]
truncated.docx   format=zip ext_hint=.docx status=no_history_available limits=['ooxml.tamper']
unknown.dat      format=unknown ext_hint=.dat status=no_history_available limits=['unsupported_format']
empty.pdf        format=empty ext_hint=.pdf status=no_history_available limits=['all']
```

## 13. Cross-tool readiness (same bytes to every detector; certificate stays outside)
```
$ docforensics-fixtures export-artifact cbcf5986ad5 --out ./tool_input.pdf ; sha256sum tool_input.pdf
8cde72109d6611c15891c66ad37eed8bc2376ea5f73ef672ea7b6e745bf45f3d  tool_input.pdf
$ docforensics-fixtures record-external cbcf5986ad5 --name DetectorB --version 1.0 --result no_traces_found --artifact-sha256 8cde72109d6611c15891c66ad37eed8bc2376ea5f73ef672ea7b6e745bf45f3d
$E/bench/evaluations/cbcf5986ad5.json
$ # a detector that hashed different bytes is refused:
refused: same-byte rule: detector did not analyse the certified artifact bytes
```
