#!/bin/bash
# 볼트 원본 수정 후 실행: 래핑 빌드 → 커밋 → 푸시 (GitHub Pages 자동 배포)
set -e
cd "$(dirname "$0")"
python3 build.py
git add -A
git commit -m "사이트 갱신: $(date +%F)

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
git push
