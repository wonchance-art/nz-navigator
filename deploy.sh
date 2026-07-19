#!/bin/bash
# Git 원본 검증·파생 자산 빌드 → 커밋 → 푸시 (GitHub Pages 자동 배포)
set -e
cd "$(dirname "$0")"
python3 build.py
git add -A
git commit -m "사이트 갱신: $(date +%F)

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
git push
