import os
from datetime import datetime
from html import escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
)

def register_fonts(font_dir='fonts/'):
    nanum = os.path.join(font_dir, 'NanumGothic.ttf')
    nanum_bold = os.path.join(font_dir, 'NanumGothicBold.ttf')
    if os.path.exists(nanum):
        pdfmetrics.registerFont(TTFont('NanumGothic', nanum))
    if os.path.exists(nanum_bold):
        pdfmetrics.registerFont(TTFont('NanumGothic-Bold', nanum_bold))

def safe_escape(text):
    return escape(str(text)) if text else ''

def generate_pdf_report(crawled_urls, extraction_results, vulnerabilities, attempts, output_path='results/fuzzer_report.pdf'):
    register_fonts()
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    doc = SimpleDocTemplate(output_path, pagesize=A4, rightMargin=30, leftMargin=30, topMargin=40, bottomMargin=30)
    styles = getSampleStyleSheet()

    custom_styles = {
        'TitleCustom': ParagraphStyle(name='TitleCustom', fontName='NanumGothic-Bold', fontSize=24, alignment=1, spaceAfter=30),
        'Date': ParagraphStyle(name='Date', fontName='NanumGothic', fontSize=12, alignment=1, spaceAfter=50),
        'SectionHeader': ParagraphStyle(name='SectionHeader', fontName='NanumGothic-Bold', fontSize=18, spaceAfter=20),
        'NormalText': ParagraphStyle(name='NormalText', fontName='NanumGothic', fontSize=10, spaceAfter=6),
        'TOCHeader': ParagraphStyle(name='TOCHeader', fontName='NanumGothic-Bold', fontSize=20, spaceAfter=20)
    }
    for k, v in custom_styles.items():
        styles.add(v)

    flowables = []
    flowables.append(Spacer(1, 200))
    flowables.append(Paragraph("웹 퍼저 리포트", styles['TitleCustom']))
    flowables.append(Paragraph(datetime.now().strftime('%Y-%m-%d %H:%M:%S'), styles['Date']))
    flowables.append(PageBreak())

    flowables.append(Paragraph("목차", styles['TOCHeader']))
    toc_items = ["1. 크롤링 URL", "2. 입력 폼 정보", "3. 퍼징 탐지 결과"]
    for item in toc_items:
        flowables.append(Paragraph(item, styles['NormalText']))
    flowables.append(PageBreak())

    flowables.append(Paragraph("1. 크롤링 URL", styles['SectionHeader']))
    if crawled_urls:
        data = [[Paragraph("크롤링한 URL", styles['NormalText'])]] + [[Paragraph(safe_escape(url), styles['NormalText'])] for url in crawled_urls]
        table = Table(data, colWidths=[480])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (0, 0), colors.whitesmoke),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.black),
            ('FONTNAME', (0, 0), (-1, 0), 'NanumGothic-Bold'),
            ('FONTNAME', (0, 1), (-1, -1), 'NanumGothic'),
        ]))
        flowables.append(table)
    else:
        flowables.append(Paragraph("크롤링한 URL이 없습니다.", styles['NormalText']))
    flowables.append(PageBreak())

    flowables.append(Paragraph("2. 입력 폼 정보", styles['SectionHeader']))
    if extraction_results:
        data = [["URL", "폼 액션", "메소드", "입력 필드"]]
        for result in extraction_results:
            for form in result.get('forms', []):
                inputs = ', '.join([f"{i.get('name')} ({i.get('type')})" for i in form.get('inputs', [])])
                data.append([
                    Paragraph(safe_escape(result.get('url', '')), styles['NormalText']),
                    Paragraph(safe_escape(form.get('action', '')), styles['NormalText']),
                    Paragraph(safe_escape(form.get('method', '').upper()), styles['NormalText']),
                    Paragraph(safe_escape(inputs), styles['NormalText'])
                ])
        table = Table(data, colWidths=[120, 120, 60, 180])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.black),
            ('FONTNAME', (0, 0), (-1, 0), 'NanumGothic-Bold'),
            ('FONTNAME', (0, 1), (-1, -1), 'NanumGothic'),
        ]))
        flowables.append(table)
    else:
        flowables.append(Paragraph("폼 정보가 없습니다.", styles['NormalText']))
    flowables.append(PageBreak())

    flowables.append(Paragraph("3. 퍼징 탐지 결과", styles['SectionHeader']))
    if attempts:
        data = [["카테고리", "폼 액션", "페이로드", "탐지 결과", "HTTP 상태", "응답 시간"]]
        for attempt in attempts:
            data.append([
                Paragraph(safe_escape(attempt.get('category', '')), styles['NormalText']),
                Paragraph(safe_escape(attempt.get('form_action', '')), styles['NormalText']),
                Paragraph(safe_escape(attempt.get('payload', '')), styles['NormalText']),
                Paragraph(safe_escape(attempt.get('result', '')), styles['NormalText']),
                Paragraph(str(attempt.get('status', '')), styles['NormalText']),
                Paragraph(f"{attempt.get('elapsed', 0):.2f}s", styles['NormalText'])
            ])
        table = Table(data, colWidths=[60, 120, 120, 90, 60, 60])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.black),
            ('FONTNAME', (0, 0), (-1, 0), 'NanumGothic-Bold'),
            ('FONTNAME', (0, 1), (-1, -1), 'NanumGothic'),
        ]))
        flowables.append(table)
    else:
        flowables.append(Paragraph("퍼징 탐지 결과가 없습니다.", styles['NormalText']))

    doc.build(flowables)
