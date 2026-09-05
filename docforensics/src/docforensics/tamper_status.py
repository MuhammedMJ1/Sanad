"""Derive the three-state ``tamper_status`` block from findings + evidence.

HARD RULES (from the spec):
  * ``no_history_available`` is never proof of authenticity.
  * ``no_traces_found`` means only that the implemented analysis found no
    supported trace; it is never a claim that the file was never modified.
"""
from __future__ import annotations

from typing import Any

from .models import Finding

TRACES_FOUND = "traces_found"
NO_TRACES = "no_traces_found"
NO_HISTORY = "no_history_available"

EXPLANATION_AR = {
    TRACES_FOUND: (
        "عُثر على مؤشرات فنية قابلة للرصد داخل الملف تتوافق مع حدوث تعديل أو "
        "إعادة حفظ. راجع الأدلة التفصيلية لتحديد قوتها."
    ),
    NO_TRACES: (
        "لم يعثر التحليل على آثار تعديل ضمن الأدلة التي أمكن فحصها. هذه النتيجة "
        "لا تثبت أن الملف لم يُعدّل سابقاً."
    ),
    NO_HISTORY: (
        "لا يحتوي الملف على تاريخ أو آثار بنيوية كافية تسمح بإثبات أو نفي وجود "
        "تعديل سابق اعتماداً على الملف وحده."
    ),
}

EXPLANATION_EN = {
    TRACES_FOUND: "Observable technical indicators consistent with post-creation "
                  "modification or re-saving were found. Review the detailed evidence "
                  "for their strength.",
    NO_TRACES: "No supported tamper trace was identified in the evidence that could be "
               "inspected. This does not prove the file was never modified.",
    NO_HISTORY: "The file does not carry enough history or structural residue to "
                "confirm or refute earlier modification from the file alone.",
}


def history_available(detected_format: str, parsed: dict[str, Any]) -> bool:
    """Is there inspectable historical evidence at all?"""
    if detected_format == "pdf":
        pdf = parsed.get("pdf") or {}
        return bool(
            pdf.get("revision_count", 0) > 1
            or pdf.get("docinfo")
            or pdf.get("xmp_raw")
            or pdf.get("trailer_id")
        )
    if detected_format in ("jpeg", "png"):
        img = parsed.get("image") or {}
        return bool(img.get("exif") or img.get("text_chunks") or img.get("app_segments_meta"))
    if detected_format in ("docx", "xlsx", "pptx"):
        ox = parsed.get("ooxml") or {}
        return bool(ox.get("core") or ox.get("app") or ox.get("entries"))
    return False


def compute(detected_format: str, parsed: dict[str, Any], findings: list[Finding]) -> dict[str, Any]:
    traces = [f for f in findings if f.is_trace]
    pdf = parsed.get("pdf") or {}
    recovered = [
        f.evidence for f in findings if f.rule_id == "pdf.tamper.recovered_prior_metadata"
    ]
    if traces:
        state = TRACES_FOUND
    elif history_available(detected_format, parsed):
        state = NO_TRACES
    else:
        state = NO_HISTORY
    return {
        "state": state,
        "explanation_ar": EXPLANATION_AR[state],
        "explanation_en": EXPLANATION_EN[state],
        "revisions_found": int(pdf.get("revision_count", 0) or 0),
        "recovered_prior_metadata": [
            item for ev in recovered for item in ev.get("items", [])
        ],
        "trace_rule_ids": sorted({f.rule_id for f in traces}),
        "proof_of_authenticity": False,   # never implied by any state
    }
