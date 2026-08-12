"""Build a PDF table report from Prisma AIRS AI Model Security Data Plane scans.

API reference: https://pan.dev/prisma-airs-model-security/api/aisecuritymodel/aisecuritymodel/
"""

from __future__ import annotations

import datetime as dt
from pathlib import Path
from typing import Any
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from model_security_client.api import ModelSecurityAPIClient

from prisma_airs_modelscan.scans import (
    DATA_PLANE_PAGE_CAP as _DATA_PLANE_PAGE_CAP,
    fetch_all_scan_files as _fetch_all_scan_files,
    fetch_all_scan_violations as _fetch_all_scan_violations,
    index_violations_by_file as _index_violations_by_file,
    viol_count_for_file as _viol_count_for_file,
)

DOC_REF = "https://pan.dev/prisma-airs-model-security/api/aisecuritymodel/aisecuritymodel/"

_MAX_DETAIL_ROWS_EVAL = 16
_MAX_FILE_ROWS_PDF = 100
_MAX_VIOL_GROUPS = 35
_MAX_VIOL_ROWS_PER_FILE = 14
_DESC_MAX = 72
_DESC_VIOL_FILE = 56
_RULE_MAX = 32
_URI_MAX_DETAIL = 84


def _dt_utc(scan_dt: dt.datetime | None) -> str:
    if scan_dt is None:
        return ""
    if scan_dt.tzinfo is None:
        scan_dt = scan_dt.replace(tzinfo=dt.timezone.utc)
    return scan_dt.astimezone(dt.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def _dt_short(scan_dt: dt.datetime | None) -> str:
    if scan_dt is None:
        return ""
    if scan_dt.tzinfo is None:
        scan_dt = scan_dt.replace(tzinfo=dt.timezone.utc)
    return scan_dt.astimezone(dt.timezone.utc).strftime("%m-%d %H:%M")


def _labels_str(scan: Any) -> str:
    if not scan.labels:
        return ""
    parts: list[str] = []
    for item in scan.labels:
        if item is None:
            continue
        parts.append(f"{item.key}={item.value}")
    return "; ".join(parts)


def _rules_pft(scan: Any) -> str:
    es = scan.eval_summary
    if es is None:
        return ""
    p, f, t = es.rules_passed, es.rules_failed, es.total_rules
    return f"{p or 0}/{f or 0}/{t or 0}"


def _files_sk(scan: Any) -> str:
    s, k = scan.total_files_scanned, scan.total_files_skipped
    if s is None and k is None:
        return ""
    return f"{s or 0}/{k or 0}"


def _trunc(s: str, n: int) -> str:
    s = (s or "").strip().replace("\n", " ")
    if len(s) <= n:
        return s
    return s[: n - 1] + "…"


def _formats_cell(formats: list[str] | None) -> str:
    if not formats:
        return ""
    return _trunc(", ".join(formats), 90)


def _remediation_snippet(rem: Any) -> str:
    if rem is None:
        return ""
    parts: list[str] = []
    steps = getattr(rem, "steps", None) or []
    if steps:
        parts.append(_trunc("; ".join(str(s) for s in steps[:2]), 60))
    url = getattr(rem, "url", None) or ""
    if url:
        parts.append(_trunc(str(url), 48))
    return " | ".join(parts) if parts else ""


def _make_para_styles() -> tuple[Any, Any, Any, Any, Any, Any]:
    styles = getSampleStyleSheet()
    normal = styles["Normal"]
    title_sty = styles["Title"]
    h2 = styles["Heading2"]

    tiny = ParagraphStyle(
        "tiny",
        parent=normal,
        fontName="Helvetica",
        fontSize=5,
        leading=6,
        spaceAfter=0,
        spaceBefore=0,
    )
    tiny_bold = ParagraphStyle(
        "tinyBold",
        parent=tiny,
        fontName="Helvetica-Bold",
        fontSize=5.5,
        leading=6.5,
    )
    micro = ParagraphStyle(
        "micro",
        parent=normal,
        fontName="Helvetica",
        fontSize=4.5,
        leading=5.5,
    )
    return title_sty, h2, normal, tiny, tiny_bold, micro


def _table_base_style() -> list[tuple]:
    return [
        ("GRID", (0, 0), (-1, -1), 0.2, colors.HexColor("#b0b0b0")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 0.5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 0.5),
        ("LEFTPADDING", (0, 0), (-1, -1), 2),
        ("RIGHTPADDING", (0, 0), (-1, -1), 2),
    ]


def _append_scan_detail_one_page(
    story: list[Any],
    scan: Any,
    client: ModelSecurityAPIClient,
    *,
    include_evaluations: bool,
    tiny: Any,
    tiny_bold: Any,
    micro: Any,
) -> None:
    """Scan header, optional rule evaluations, file inventory, violations grouped by file."""
    uid = str(scan.uuid)
    uri = _trunc(scan.model_uri or "", _URI_MAX_DETAIL)

    banner = (
        f"<b>{escape(uid)}</b> &nbsp;|&nbsp; Outcome: <b>{escape(str(scan.eval_outcome))}</b> "
        f"&nbsp;|&nbsp; Rules P/F/T: {escape(_rules_pft(scan))} "
        f"&nbsp;|&nbsp; Files sc/skip: {escape(_files_sk(scan))}"
    )
    summary = Paragraph(
        f"Model: {escape(uri)} &nbsp;|&nbsp; Source: {escape(str(scan.source_type))} "
        f"&nbsp;|&nbsp; Origin: {escape(str(scan.scan_origin))} "
        f"&nbsp;|&nbsp; SG: {escape(_trunc(scan.security_group_name or '', 38))} "
        f"&nbsp;|&nbsp; Scanner: {escape(_trunc(scan.scanner_version or '', 12))}",
        micro,
    )
    label_line: list[Any] = []
    if _labels_str(scan):
        label_line = [
            Paragraph(f"Labels: {escape(_trunc(_labels_str(scan), 180))}", micro),
        ]

    ev_rows: list[list[Any]] | None = None
    if include_evaluations:
        ev_rows = []
        try:
            evl = client.get_scan_evaluations(
                scan_uuid=scan.uuid, limit=_DATA_PLANE_PAGE_CAP, skip=0
            )
            ev_list = list(evl.evaluations)
            ev_total = len(ev_list)
            ev_trim = ev_list[:_MAX_DETAIL_ROWS_EVAL]
            ev_hdr = ["Rule", "Res", "V#", "State", "Rule summary"]
            ev_rows.append([Paragraph(escape(h), tiny_bold) for h in ev_hdr])
            for ev in ev_trim:
                ev_rows.append(
                    [
                        Paragraph(escape(_trunc(ev.rule_name, _RULE_MAX)), tiny),
                        Paragraph(escape(str(ev.result)[:12]), tiny),
                        Paragraph(escape(str(ev.violation_count)), tiny),
                        Paragraph(escape(str(ev.rule_instance_state)[:14]), tiny),
                        Paragraph(escape(_trunc(ev.rule_description, _DESC_MAX)), tiny),
                    ]
                )
            if ev_total > len(ev_trim):
                ev_rows.append(
                    [
                        Paragraph(
                            escape(f"(+{ev_total - len(ev_trim)} more evaluations omitted)"), tiny
                        )
                    ]
                    + [Paragraph("", tiny)] * 4
                )
        except Exception as exc:  # noqa: BLE001
            ev_rows.append(
                [Paragraph(escape(f"Evaluations: {exc}"), tiny)] + [Paragraph("", tiny)] * 4
            )

    scan_files: list[Any] = []
    all_violations: list[Any] = []
    files_err: str | None = None
    viol_err: str | None = None
    try:
        scan_files = _fetch_all_scan_files(client, scan.uuid)
    except Exception as exc:  # noqa: BLE001
        files_err = str(exc)
    try:
        all_violations = _fetch_all_scan_violations(client, scan.uuid)
    except Exception as exc:  # noqa: BLE001
        viol_err = str(exc)

    by_path = _index_violations_by_file(all_violations)

    file_rows: list[list[Any]] = []
    f_hdr = [
        "Path",
        "Parent",
        "Type",
        "Result",
        "Formats",
        "Blob ID",
        "File UUID",
        "#Viol",
        "Updated",
    ]
    file_rows.append([Paragraph(escape(h), tiny_bold) for h in f_hdr])

    if files_err:
        file_rows.append(
            [Paragraph(escape(f"Files API: {files_err}"), tiny)]
            + [Paragraph("", tiny)] * 8
        )
    elif not scan_files:
        file_rows.append(
            [Paragraph(escape("(no file rows returned)"), tiny)] + [Paragraph("", tiny)] * 8
        )
    else:
        trimmed = scan_files[:_MAX_FILE_ROWS_PDF]
        for f in trimmed:
            vc = str(_viol_count_for_file(f.path, by_path))
            file_rows.append(
                [
                    Paragraph(escape(_trunc(f.path, 42)), tiny),
                    Paragraph(escape(_trunc(f.parent_path, 28)), tiny),
                    Paragraph(escape(str(f.type)[:12]), tiny),
                    Paragraph(escape(str(f.result)[:10]), tiny),
                    Paragraph(escape(_formats_cell(f.formats)), tiny),
                    Paragraph(escape(_trunc(f.blob_id or "", 20)), tiny),
                    Paragraph(escape(str(f.uuid)[:13] + "…"), tiny),
                    Paragraph(escape(vc), tiny),
                    Paragraph(escape(_dt_short(f.updated_at)), tiny),
                ]
            )
        if len(scan_files) > len(trimmed):
            file_rows.append(
                [
                    Paragraph(
                        escape(f"(+{len(scan_files) - len(trimmed)} more files omitted from PDF)"),
                        tiny,
                    )
                ]
                + [Paragraph("", tiny)] * 8
            )

    w = landscape(A4)[0] - 72
    ev_w = [w * 0.14, w * 0.09, w * 0.06, w * 0.11, w * 0.60]
    fw = [
        w * 0.22,
        w * 0.12,
        w * 0.06,
        w * 0.07,
        w * 0.16,
        w * 0.10,
        w * 0.11,
        w * 0.05,
        w * 0.11,
    ]

    eval_flow: list[Any] = []
    if include_evaluations and ev_rows is not None:
        te = Table(ev_rows, colWidths=ev_w, hAlign="LEFT")
        te.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#dde8f0")),
                    *_table_base_style(),
                ]
            )
        )
        eval_flow = [
            Paragraph("Rule evaluations", tiny_bold),
            te,
            Spacer(1, 0.04 * inch),
        ]

    tf = Table(file_rows, colWidths=fw, hAlign="LEFT")
    tf.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e0efe0")),
                *_table_base_style(),
            ]
        )
    )

    viol_section: list[Any] = []
    viol_section.append(Paragraph("Violations by file (rule_violations API)", tiny_bold))
    viol_section.append(Spacer(1, 0.03 * inch))

    if viol_err:
        viol_section.append(Paragraph(escape(f"Violations API: {viol_err}"), micro))
    else:
        paths_ordered = sorted(by_path.keys())
        shown_groups = 0
        for fpath in paths_ordered:
            if shown_groups >= _MAX_VIOL_GROUPS:
                viol_section.append(
                    Paragraph(
                        escape(
                            f"(+{len(paths_ordered) - shown_groups} more file paths with "
                            "violations omitted from PDF)"
                        ),
                        tiny,
                    )
                )
                break
            vs = by_path[fpath]
            title = (
                "Unspecified file / not tied to a path"
                if fpath == "__UNSPECIFIED__"
                else fpath
            )
            viol_section.append(Paragraph(f"<b>{escape(_trunc(title, 120))}</b>", tiny_bold))
            v_hdr = [
                "Rule",
                "Rule desc",
                "Threat",
                "Module",
                "Op",
                "Finding",
                "State",
                "UUID",
                "Fix",
            ]
            vr = [[Paragraph(escape(h), tiny_bold) for h in v_hdr]]
            trim_v = vs[:_MAX_VIOL_ROWS_PER_FILE]
            for v in trim_v:
                vr.append(
                    [
                        Paragraph(escape(_trunc(v.rule_name, 22)), tiny),
                        Paragraph(escape(_trunc(getattr(v, "rule_description", "") or "", 36)), tiny),
                        Paragraph(escape(_trunc(str(v.threat or ""), 14)), tiny),
                        Paragraph(escape(_trunc(v.module or "", 12)), tiny),
                        Paragraph(escape(_trunc(v.operator or "", 10)), tiny),
                        Paragraph(escape(_trunc(v.description, 50)), tiny),
                        Paragraph(escape(str(v.rule_instance_state)[:10]), tiny),
                        Paragraph(escape(str(v.uuid)[:10] + "…"), tiny),
                        Paragraph(escape(_remediation_snippet(v.remediation)), tiny),
                    ]
                )
            if len(vs) > len(trim_v):
                vr.append(
                    [Paragraph(escape(f"(+{len(vs) - len(trim_v)} more for this path)"), tiny)]
                    + [Paragraph("", tiny)] * 8
                )
            vw = [
                w * 0.09,
                w * 0.14,
                w * 0.07,
                w * 0.06,
                w * 0.05,
                w * 0.26,
                w * 0.06,
                w * 0.07,
                w * 0.15,
            ]
            vt = Table(vr, colWidths=vw, hAlign="LEFT")
            vt.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f0e6e8")),
                        *_table_base_style(),
                    ]
                )
            )
            viol_section.append(vt)
            viol_section.append(Spacer(1, 0.06 * inch))
            shown_groups += 1

    inner: list[Any] = [
        Paragraph(banner, tiny_bold),
        summary,
        *label_line,
        Spacer(1, 0.03 * inch),
        *eval_flow,
        Paragraph("Files in scan (per-file schema from /v1/scans/{id}/files)", tiny_bold),
        tf,
        Spacer(1, 0.04 * inch),
        *viol_section,
    ]
    # Detail blocks are often multi-page; keep only the header if tiny
    story.extend(inner)


def write_scans_pdf(
    output: Path,
    scans: list[Any],
    *,
    base_url: str,
    total_items_hint: int | None,
    include_evaluations: bool,
    client: ModelSecurityAPIClient | None,
) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    doc = SimpleDocTemplate(
        str(output),
        pagesize=landscape(A4),
        leftMargin=36,
        rightMargin=36,
        topMargin=36,
        bottomMargin=36,
    )
    title_sty, h2, normal, tiny, tiny_bold, micro = _make_para_styles()
    thead = tiny.clone("thead")
    thead.fontName = "Helvetica-Bold"

    story: list[Any] = []

    story.append(Paragraph("Prisma AIRS AI Model Security — Scan report", title_sty))
    story.append(Paragraph(f"API reference: {escape(DOC_REF)}", normal))
    story.append(Spacer(1, 0.12 * inch))
    story.append(
        Paragraph(
            f"Generated: {_dt_utc(dt.datetime.now(dt.timezone.utc))}",
            normal,
        )
    )
    story.append(Paragraph(f"Base URL: {escape(base_url)}", normal))
    summary = f"Scans in this PDF: {len(scans)}"
    if total_items_hint is not None:
        summary += (
            f" (API total_items on first page: {total_items_hint}; "
            "filters may reduce rows)."
        )
    story.append(Paragraph(summary, normal))
    if client and scans:
        extra = (
            "Per-scan detail pages include the file inventory and violations-by-file tables "
            "(extra API calls). "
        )
        if include_evaluations:
            extra += (
                "This run also includes per-rule evaluation rows (--include-evaluations)."
            )
        else:
            extra += "Add --include-evaluations for the per-rule evaluation table."
        story.append(Paragraph(extra, normal))
    story.append(Spacer(1, 0.16 * inch))

    if not scans:
        story.append(Paragraph("No scans returned for the current filters.", normal))
        doc.build(story)
        return

    hdr = [
        "Scan UUID (prefix)",
        "Created (UTC)",
        "Model URI / path",
        "Source",
        "Origin",
        "Security group",
        "Outcome",
        "Rules P/F/T",
        "Files sc/skip",
        "Scanner",
        "Labels",
    ]
    data: list[list[Any]] = [[Paragraph(escape(h), thead) for h in hdr]]

    for scan in scans:
        uid = str(scan.uuid)
        uri = scan.model_uri or ""
        if len(uri) > 200:
            uri = uri[:197] + "..."
        data.append(
            [
                Paragraph(escape(uid[:8] + "…"), tiny),
                Paragraph(escape(_dt_utc(scan.created_at)), tiny),
                Paragraph(escape(uri), tiny),
                Paragraph(escape(str(scan.source_type)), tiny),
                Paragraph(escape(str(scan.scan_origin)), tiny),
                Paragraph(escape((scan.security_group_name or "")[:44]), tiny),
                Paragraph(escape(str(scan.eval_outcome)), tiny),
                Paragraph(escape(_rules_pft(scan)), tiny),
                Paragraph(escape(_files_sk(scan)), tiny),
                Paragraph(escape((scan.scanner_version or "")[:18]), tiny),
                Paragraph(escape(_labels_str(scan)[:220]), tiny),
            ]
        )

    col_widths = [52, 72, 198, 38, 54, 76, 48, 44, 44, 44, 118]
    tbl = Table(data, colWidths=col_widths, repeatRows=1)
    tbl.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e8e8e8")),
                ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                (
                    "ROWBACKGROUNDS",
                    (0, 1),
                    (-1, -1),
                    [colors.whitesmoke, colors.white],
                ),
            ]
        )
    )
    story.append(tbl)

    if client and scans:
        story.append(PageBreak())
        story.append(Paragraph("Per-scan detail: files + violations", h2))
        story.append(Spacer(1, 0.08 * inch))
        for i, scan in enumerate(scans):
            if i > 0:
                story.append(PageBreak())
            _append_scan_detail_one_page(
                story,
                scan,
                client,
                include_evaluations=include_evaluations,
                tiny=tiny,
                tiny_bold=tiny_bold,
                micro=micro,
            )

    story.append(PageBreak())
    story.append(Paragraph("Full scan UUID reference", h2))
    story.append(Spacer(1, 0.06 * inch))
    ref = [
        [Paragraph(escape("Prefix"), thead), Paragraph(escape("Full UUID"), thead)],
    ]
    for scan in scans:
        uid = str(scan.uuid)
        ref.append(
            [
                Paragraph(escape(uid[:8] + "…"), tiny),
                Paragraph(escape(uid), tiny),
            ]
        )
    rt = Table(ref, colWidths=[64, 430])
    rt.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e8e8e8")),
                ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ]
        )
    )
    story.append(rt)

    doc.build(story)
