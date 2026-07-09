#!/usr/bin/env python3
"""볼트 원본(Artifact 규격: doctype/head/body 없음)을 정식 HTML 문서로 래핑 — 한국어판 + 일본어판."""
import pathlib

VAULT = pathlib.Path.home() / 'Library/Mobile Documents/iCloud~md~obsidian/Documents/nz'
ROOT = pathlib.Path(__file__).parent

PAGES = [
    {
        'src': VAULT / 'index.html',
        'out': ROOT / 'index.html',
        'lang': 'ko',
        'title': 'NZ 영주권 내비게이터',
        'meta': '''<meta name="description" content="뉴질랜드 체류 설계도 — 비자·영주권 로드맵, 시나리오, 직군·도시 가이드, 비용 계산기. 2026-07 공식 검증 데이터.">
<meta property="og:title" content="NZ 영주권 내비게이터">
<meta property="og:description" content="어떤 비자로 오든 — 영주권까지의 조건·비용·타임라인을 설계합니다.">
<meta property="og:type" content="website">''',
    },
    {
        'src': VAULT / 'index.ja.html',
        'out': ROOT / 'ja' / 'index.html',
        'lang': 'ja',
        'title': 'NZ永住権ナビゲーター',
        'meta': '''<meta name="description" content="ニュージーランド滞在設計図 — ビザ・永住権ロードマップ、シナリオ、職種・都市ガイド、費用計算機。2026-07公式検証データ。">
<meta property="og:title" content="NZ永住権ナビゲーター">
<meta property="og:description" content="どのビザで来ても — 永住権までの条件・費用・タイムラインを設計。">
<meta property="og:type" content="website">''',
    },
]

for p in PAGES:
    if not p['src'].exists():
        print(f"skip — {p['src']} 없음")
        continue
    content = p['src'].read_text(encoding='utf-8')
    cut = content.index('</style>') + len('</style>')
    head_part = content[:cut]
    body_part = content[cut:].lstrip('\n')

    title_tag = f"<title>{p['title']}</title>"
    assert title_tag in head_part, f"{p['src'].name}: title 불일치 — '{p['title']}'"
    head_part = head_part.replace(title_tag, title_tag + '\n' + p['meta'], 1)

    doc = f'''<!DOCTYPE html>
<html lang="{p['lang']}">
<head>
{head_part}
</head>
<body>
{body_part}
</body>
</html>
'''
    p['out'].parent.mkdir(exist_ok=True)
    p['out'].write_text(doc, encoding='utf-8')
    print(f"OK — wrapped {len(doc):,} bytes -> {p['out']}")
