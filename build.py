#!/usr/bin/env python3
"""볼트 원본(Artifact 규격: doctype/head/body 없음)을 정식 HTML 문서로 래핑."""
import sys, pathlib

SRC = pathlib.Path.home() / 'Library/Mobile Documents/iCloud~md~obsidian/Documents/nz/index.html'
OUT = pathlib.Path(__file__).parent / 'index.html'

content = SRC.read_text(encoding='utf-8')
cut = content.index('</style>') + len('</style>')
head_part = content[:cut]
body_part = content[cut:].lstrip('\n')

EXTRA_META = '''<meta name="description" content="뉴질랜드 체류 설계도 — 비자·영주권 로드맵, 시나리오, 직군·도시 가이드, 비용 계산기. 2026-07 공식 검증 데이터.">
<meta property="og:title" content="NZ 영주권 내비게이터">
<meta property="og:description" content="어떤 비자로 오든 — 영주권까지의 조건·비용·타임라인을 설계합니다.">
<meta property="og:type" content="website">'''

head_part = head_part.replace('<title>NZ 영주권 내비게이터</title>',
                              '<title>NZ 영주권 내비게이터</title>\n' + EXTRA_META, 1)

doc = f'''<!DOCTYPE html>
<html lang="ko">
<head>
{head_part}
</head>
<body>
{body_part}
</body>
</html>
'''
OUT.write_text(doc, encoding='utf-8')
print(f'OK — wrapped {len(doc):,} bytes -> {OUT}')
