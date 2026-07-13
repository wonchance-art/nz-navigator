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
        'title': 'NZ NAVI',
        'meta': '''<meta name="description" content="뉴질랜드 체류 설계도 — 비자·영주권 로드맵, 시나리오, 직군·도시 가이드, 비용 계산기. 2026-07 공식 검증 데이터.">
<meta property="og:title" content="NZ NAVI — 뉴질랜드 영주권 내비게이터">
<meta property="og:description" content="어떤 비자로 오든 — 영주권까지의 조건·비용·타임라인을 설계합니다.">
<meta property="og:type" content="website">
<meta property="og:url" content="https://wonchance-art.github.io/nz-navigator/">
<meta property="og:image" content="https://wonchance-art.github.io/nz-navigator/og-image.png">
<meta property="og:image:width" content="1200">
<meta property="og:image:height" content="630">
<meta name="twitter:card" content="summary_large_image">''',
    },
    {
        'src': VAULT / 'index.ca.html',
        'out': ROOT / 'ca' / 'index.html',
        'lang': 'ko',
        'title': 'CA NAVI',
        'meta': '''<meta name="description" content="캐나다 체류 설계도 — 워홀(IEC)·영주권(Express Entry·PNP) 로드맵, 직군·도시 가이드, CRS·실수령 계산기.">
<meta property="og:title" content="CA NAVI — 캐나다 영주권 내비게이터">
<meta property="og:description" content="어떤 비자로 가든 — 영주권까지의 조건·비용·타임라인을 설계합니다.">
<meta property="og:type" content="website">
<meta property="og:url" content="https://wonchance-art.github.io/nz-navigator/ca/">
<meta property="og:image" content="https://wonchance-art.github.io/nz-navigator/ca/og-image.png">
<meta property="og:image:width" content="1200">
<meta property="og:image:height" content="630">
<meta name="twitter:card" content="summary_large_image">''',
    },
    # AU NAVI — 감수 후 재공개 예정 (2026-07-13)
    {
        'skip': True,
        'src': VAULT / 'index.au.html',
        'out': ROOT / 'au' / 'index.html',
        'lang': 'ko',
        'title': 'AU NAVI',
        'meta': '''<meta name="description" content="호주 체류 설계도 — 워홀(417)·영주권(포인트 테스트·고용주 스폰서) 로드맵, 직군·도시 가이드, 실수령 계산기.">
<meta property="og:title" content="AU NAVI — 호주 영주권 내비게이터">
<meta property="og:description" content="어떤 비자로 가든 — 영주권까지의 조건·비용·타임라인을 설계합니다.">
<meta property="og:type" content="website">
<meta property="og:url" content="https://wonchance-art.github.io/nz-navigator/au/">
<meta property="og:image" content="https://wonchance-art.github.io/nz-navigator/au/og-image.png">
<meta property="og:image:width" content="1200">
<meta property="og:image:height" content="630">
<meta name="twitter:card" content="summary_large_image">''',
    },
    {
        'src': VAULT / 'index.ja.html',
        'out': ROOT / 'ja' / 'index.html',
        'lang': 'ja',
        'title': 'NZ NAVI',
        'meta': '''<meta name="description" content="ニュージーランド滞在設計図 — ビザ・永住権ロードマップ、シナリオ、職種・都市ガイド、費用計算機。2026-07公式検証データ。">
<meta property="og:title" content="NZ NAVI — NZ永住権ナビ">
<meta property="og:description" content="どのビザで来ても — 永住権までの条件・費用・タイムラインを設計。">
<meta property="og:type" content="website">
<meta property="og:url" content="https://wonchance-art.github.io/nz-navigator/ja/">
<meta property="og:image" content="https://wonchance-art.github.io/nz-navigator/ja/og-image.png">
<meta property="og:image:width" content="1200">
<meta property="og:image:height" content="630">
<meta name="twitter:card" content="summary_large_image">''',
    },
]

for p in PAGES:
    if p.get('skip'):
        print(f"skip — {p['title']} (비활성)")
        continue
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
