#!/bin/bash
# aws-cdk の統合テストのスナップショット（実際にデプロイされたテンプレート、約 3,000 枚、36MB）を
# sparse clone する。scripts/corpus-sweep.ts --check <dir>/packages の入力。
# CORPUS_REF を上げたら、--check の差分を見て rules/_corpus-accepted.txt を直す。
set -eu
DIR="${1:?usage: fetch-corpus.sh <dir>}"
CORPUS_REF="${CORPUS_REF:-726f74dc7cb8104ace30bc1de07c4f7d15bb01be}"
git init -q "$DIR"
cd "$DIR"
git remote add origin https://github.com/aws/aws-cdk.git 2>/dev/null || true
git sparse-checkout set --no-cone '/packages/@aws-cdk-testing/framework-integ/test/**/*.snapshot/*.template.json'
git fetch -q --depth 1 --filter=blob:none origin "$CORPUS_REF"
git checkout -q FETCH_HEAD
echo "$(find packages -name '*.template.json' | wc -l) templates at $CORPUS_REF"
