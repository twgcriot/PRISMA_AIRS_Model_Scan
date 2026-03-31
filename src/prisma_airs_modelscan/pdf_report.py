"""Build a PDF table report from Prisma AIRS AI Model Security Data Plane scans.

API reference: https://pan.dev/prisma-airs-model-security/api/aisecuritymodel/aisecuritymodel/
"""

from __future__ import annotations

import datetime as dt
from pathlib import Path
from typing import Any
from uuid import UUID
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    KeepTogether,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from model_security_client.api import ModelSecurityAPIClient

DOC_REF = "https://pan.dev/prisma-airs-model-security/api/aisecuritymodel/aisecuritymodel/"

_MAX_DETAIL_ROWS_EVAL = 16
_MAX_DETAIL_ROWS_VIOL = 18
_DESC_MAX = 68
_RULE_MAX = 34
_URI_MAX_DETAIL = 84


def _dt_utc(scan_dt: dt.datetime | None) -> str:
    if scan_dt is None:
        return ""
    if scan_dt.tzinfo is None:
        scan_dt = scan_dt.replace(tzinfo=dt.timezone.utc)
    return scan_dt.astimezone(dt.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


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


def fetch_all_scans(
    client: ModelSecurityAPIClient,
    *,
    page_size: int,
    max_scans: int | None,
    security_group_uuid: UUID | None,
) -> tuple[list[Any], int | None]:
    scans: list[Any] = []
    skip = 0
    total_hint: int | None = None

    while True:
        batch = client.list_scans(
            limit=page_size,
            skip=skip,
            sort_order="desc",
            security_group_uuid=security_group_uuid,
        )
        if total_hint is None and batch.pagination.total_items is not None:
            total_hint = batch.pagination.total_items
        scans.extend(batch.scans)
        if len(batch.scans) < page_size:
            break
        skip += page_size
        if max_scans is not None and len(scans) >= max_scans:
            return scans[:max_scans], total_hint

    return scans, total_hint


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


def _append_scan_detail_one_page(
    story: list[Any],
    scan: Any,
    client: ModelSecurityAPIClient,
    *,
    tiny: Any,
    tiny_bold: Any,
    micro: Any,
) -> None:
    """Dense banner + rule evaluations + violations; one PageBreak precedes each call (except first)."""
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

    ev_rows: list[list[Any]] = []
    try:
        evl = client.get_scan_evaluations(scan_uuid=scan.uuid, limit=100, skip=0)
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
                [Paragraph(escape(f"(+{ev_total - len(ev_trim)} more evaluations omitted)"), tiny)]
                + [Paragraph("", tiny)] * 4
            )
    except Exception as exc:  # noqa: BLE001
        ev_rows.append(
            [Paragraph(escape(f"Evaluations: {exc}"), tiny)] + [Paragraph("", tiny)] * 4
        )

    viol_rows: list[list[Any]] = []
    try:
        viol_list_resp = client.get_scan_violations(
            scan_uuid=scan.uuid, limit=100, skip=0
        )
        viol_list = list(viol_list_resp.violations)
        viol_total = len(viol_list)
        viol_trim = viol_list[:_MAX_DETAIL_ROWS_VIOL]
        vv_hdr = ["Rule", "Threat", "File", "Detail", "State"]
        viol_rows.append([Paragraph(escape(h), tiny_bold) for h in vv_hdr])
        for v in viol_trim:
            fpath = v.file if v.file else "\u2014"
            viol_rows.append(
                [
                    Paragraph(escape(_trunc(v.rule_name, _RULE_MAX)), tiny),
                    Paragraph(escape(_trunc(str(v.threat or ""), 18)), tiny),
                    Paragraph(escape(_trunc(fpath, 26)), tiny),
                    Paragraph(escape(_trunc(v.description, _DESC_MAX)), tiny),
                    Paragraph(escape(str(v.rule_instance_state)[:12]), tiny),
                ]
            )
        if viol_total > len(viol_trim):
            viol_rows.append(
                [Paragraph(escape(f"(+{viol_total - len(viol_trim)} more violations omitted)"), tiny)]
                + [Paragraph("", tiny)] * 4
            )
    except Exception as exc:  # noqa: BLE001
        viol_rows.append(
            [Paragraph(escape(f"Violations: {exc}"), tiny)] + [Paragraph("", tiny)] * 4
        )

    w = landscape(A4)[0] - 72
    ev_w = [w * 0.14, w * 0.09, w * 0.06, w * 0.11, w * 0.60]
    vv_w = [w * 0.14, w * 0.12, w * 0.15, w * 0.51, w * 0.08]

    te = Table(ev_rows, colWidths=ev_w, hAlign="LEFT")
    te.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#dde8f0")),
                ("GRID", (0, 0), (-1, -1), 0.2, colors.HexColor("#b0b0b0")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("TOPPADDING", (0, 0), (-1, -1), 0.5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 0.5),
                ("LEFTPADDING", (0, 0), (-1, -1), 2),
                ("RIGHTPADDING", (0, 0), (-1, -1), 2),
            ]
        )
    )
    tv = Table(viol_rows, colWidths=vv_w, hAlign="LEFT")
    tv.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e8ddde")),
                ("GRID", (0, 0), (-1, -1), 0.2, colors.HexColor("#b0b0b0")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("TOPPADDING", (0, 0), (-1, -1), 0.5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 0.5),
                ("LEFTPADDING", (0, 0), (-1, -1), 2),
                ("RIGHTPADDING", (0, 0), (-1, -1), 2),
            ]
        )
    )

    inner: list[Any] = [
        Paragraph(banner, tiny_bold),
        summary,
        *label_line,
        Spacer(1, 0.03 * inch),
        Paragraph("Rule evaluations", tiny_bold),
        te,
        Spacer(1, 0.04 * inch),
        Paragraph("Violations (rule findings)", tiny_bold),
        tv,
    ]
    row_budget = len(ev_rows) + len(viol_rows)
    if row_budget <= 40:
        story.append(KeepTogether(inner))
    else:
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
    if include_evaluations and scans:
        story.append(
            Paragraph(
                "Detail section: one page per scan (evaluations + violations) with compact tables.",
                normal,
            )
        )
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

    if include_evaluations and client and scans:
        story.append(PageBreak())
        story.append(Paragraph("Per-scan evaluations and violations (one page each)", h2))
        story.append(
            Paragraph(
                "Tables use small type and row caps so summaries + evaluations + "
                "violations fit on a single landscape page when possible.",
                normal,
            )
        )
        story.append(Spacer(1, 0.1 * inch))
        for i, scan in enumerate(scans):
            if i > 0:
                story.append(PageBreak())
            _append_scan_detail_one_page(
                story, scan, client, tiny=tiny, tiny_bold=tiny_bold, micro=micro
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
