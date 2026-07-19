#!/usr/bin/env python3
"""Validate tracked Pages documents and build registry-derived assets.

The Git repository is the canonical deploy source. Older vault fragments are
deliberately not copied here: doing so could silently restore stale visa facts
after the reviewed HTML and its trust registries had already passed CI.
"""
from __future__ import annotations

import pathlib
import subprocess


ROOT = pathlib.Path(__file__).resolve().parent

PAGES = {
    'index.html': ('ko', 'NAVI — 어느 나라로 워홀·영주권?'),
    'nz/index.html': ('ko', 'NZ NAVI'),
    'ja/index.html': ('ja', 'NZ NAVI'),
    'ca/index.html': ('ko', 'CA NAVI'),
    'au/index.html': ('ko', 'AU NAVI'),
    'nz/seasonal-map.html': ('ko', '뉴질랜드 워홀 +3개월 연장 적격작업·시즌 지도'),
    'au/whv-map.html': ('ko', '호주 417 세컨·서드 지정작업 지도'),
    'verification.html': ('ko', '검증 원장 · NZ Navigator'),
}


for relative, (language, title) in PAGES.items():
    page = ROOT / relative
    if not page.is_file():
        raise FileNotFoundError(f'tracked page missing: {relative}')
    text = page.read_text(encoding='utf-8')
    if '<!doctype html>' not in text[:100].lower():
        raise ValueError(f'{relative}: complete HTML document required')
    if f'<html lang="{language}">' not in text[:300]:
        raise ValueError(f'{relative}: expected lang={language}')
    if f'<title>{title}</title>' not in text:
        raise ValueError(f'{relative}: expected title {title!r}')
    print(f'OK — tracked page {relative} ({len(text):,} bytes)')


subprocess.run(
    ['node', str(ROOT / 'scripts' / 'build_employer_assets.mjs')],
    cwd=ROOT,
    check=True,
)
subprocess.run(
    ['node', str(ROOT / 'scripts' / 'build_employer_assets.mjs'), '--check'],
    cwd=ROOT,
    check=True,
)
print('OK — employer registry compatibility assets are current')
