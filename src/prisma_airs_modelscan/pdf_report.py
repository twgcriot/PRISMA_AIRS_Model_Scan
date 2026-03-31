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
from reportlab.lib.styles import getSampleStyleSheet
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

DOC_REF = "https://pan.dev/prisma-airs-model-security/api/aisecuritymodel/aisecuritymodel/"


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


def fetch_all_scans(
    client: ModelSecurityAPIClient,
    *,
    page_size: int,
    max_scans: int | None,
    security_group_uuid: UUID | None,
) -> tuple[list[Any], int | None]:
    """Paginate ``GET /data/v1/scans`` until exhausted. Returns (scans, total_items from first page)."""
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
    styles = getSampleStyleSheet()
    title_sty = styles["Title"]
    normal = styles["Normal"]
    h2 = styles["Heading2"]
    small = normal.clone(name="small")
    small.fontSize = 6
    small.leading = 7
    thead = small.clone(name="thead")
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
            f" (management API total_items on first page: {total_items_hint}; "
            "filters and caps may reduce rows below that total)."
        )
    story.append(Paragraph(summary, normal))
    story.append(Spacer(1, 0.18 * inch))

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
                Paragraph(escape(uid[:8] + "…"), small),
                Paragraph(escape(_dt_utc(scan.created_at)), small),
                Paragraph(escape(uri), small),
                Paragraph(escape(str(scan.source_type)), small),
                Paragraph(escape(str(scan.scan_origin)), small),
                Paragraph(escape((scan.security_group_name or "")[:44]), small),
                Paragraph(escape(str(scan.eval_outcome)), small),
                Paragraph(escape(_rules_pft(scan)), small),
                Paragraph(escape(_files_sk(scan)), small),
                Paragraph(escape((scan.scanner_version or "")[:18]), small),
                Paragraph(escape(_labels_str(scan)[:220]), small),
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
        story.append(Paragraph("Per-scan rule evaluations", h2))
        story.append(Spacer(1, 0.1 * inch))
        ev_hdr = ["Rule", "Result", "Violations", "Rule state"]
        for scan in scans:
            uri_hint = (scan.model_uri or "")[:96]
            story.append(
                Paragraph(
                    f"Scan <b>{escape(str(scan.uuid))}</b> — {escape(uri_hint)}",
                    small,
                )
            )
            try:
                evl = client.get_scan_evaluations(scan_uuid=scan.uuid, limit=100, skip=0)
            except Exception as exc:  # noqa: BLE001
                story.append(Paragraph(escape(f"(evaluations unavailable: {exc})"), small))
                story.append(Spacer(1, 0.08 * inch))
                continue
            et = [[Paragraph(escape(x), thead) for x in ev_hdr]]
            for ev in evl.evaluations:
                et.append(
                    [
                        Paragraph(escape(ev.rule_name[:64]), small),
                        Paragraph(escape(str(ev.result)), small),
                        Paragraph(escape(str(ev.violation_count)), small),
                        Paragraph(escape(str(ev.rule_instance_state)[:28]), small),
                    ]
                )
            t2 = Table(et, colWidths=[230, 54, 54, 86])
            t2.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e8e8e8")),
                        ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
                        ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ]
                )
            )
            story.append(t2)
            story.append(Spacer(1, 0.14 * inch))

    story.append(PageBreak())
    story.append(Paragraph("Full scan UUID reference", h2))
    story.append(Spacer(1, 0.08 * inch))
    ref = [
        [Paragraph(escape("Prefix"), thead), Paragraph(escape("Full UUID"), thead)],
    ]
    for scan in scans:
        uid = str(scan.uuid)
        ref.append(
            [
                Paragraph(escape(uid[:8] + "…"), small),
                Paragraph(escape(uid), small),
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
