---
name: add-preflight-rule
description: cdk-preflight に新しいルールを追加する半自動パイプライン。制約の抽出（ドキュメント/エラーメッセージ）→ rule.rego と fail/pass テンプレート生成 → 重複ガードテスト → 実機再現ゲート → meta.yaml 記録 → PR 準備までを 1 セッションで行う。
---

# add-preflight-rule

cdk-preflight のルール追加パイプライン。AGENTS.md の設計原則（重複禁止・証拠必須・上流昇格）を機械的に踏む。

## 手順

1. **入力の確定**: 追加したい制約を 1 文で書く（対象リソース型、プロパティ、条件、出典 URL または実際に観測したデプロイエラーメッセージ）。
2. **重複チェック（先にやる）**: 違反最小テンプレートを書き、エンジンに直接かける:
   ```bash
   npx ts-node --project test/tsconfig.json -e "
   import { loadEngine } from './src/private/enforce';
   const e = loadEngine();
   const r = new e.RegoEngine({}).validateDetailed(new e.TemplateFile('<template>'), {});
   console.log(JSON.stringify(r.diagnostics, null, 2));"
   ```
   ERROR/FATAL（source: SCHEMA / CFN_LINT）が既に出るなら**ルールは書かない**。終了し、その旨を報告する。
3. **ルール作成**: `rules/<service>/<rule-id>/` に 4 ファイル。規約:
   - `package cdk_preflight` + `import rego.v1`、診断は `make_diag_full("<rule-id>", "ERROR", name, path, msg, fix, url)`
   - ヘルパーは `_pf_<短縮名>_` プレフィックスで一意に
   - `walk` ビルトインは無い。`to_number`/`object.get`/`flatten_list`/`resolve` で明示的に書く
   - fail テンプレートはこのルール**だけ**に違反、pass テンプレートは完全クリーン
4. **ローカルゲート**: `npx projen bundle-rules && npx jest test/rules.test.ts test/structure.test.ts` が全緑になるまで直す。
5. **実機再現ゲート**: `bash bench/verify-rule.sh <rule-id>`（要 AWS 認証）。観測したエラーメッセージと日付を `meta.yaml#repro.evidence` に記録。実機不能な制約のみ `doc-only` + 理由。
6. **仕上げ**: `npx projen build` 全緑 → ブランチ作成 → conventional commit（`feat(rules): add <rule-id>`）→ PR 本文に: 制約の出典 / 重複チェック結果 / 実機再現ログ。
