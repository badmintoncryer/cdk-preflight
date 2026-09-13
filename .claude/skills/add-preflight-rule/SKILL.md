---
name: add-preflight-rule
description: cdk-preflight に新しいルールを追加する半自動パイプライン。制約の抽出（ドキュメント/エラーメッセージ）→ rule.rego と fail/pass テンプレート生成 → 重複ガードテスト → 実機再現ゲート → meta.yaml 記録 → PR 準備まで。候補が複数ある場合はフェーズごとにセッションを分ける（「セッションの切り方」参照）。
---

# add-preflight-rule

cdk-preflight のルール追加パイプライン。AGENTS.md の設計原則（重複禁止・証拠必須）を機械的に踏む。

対象は「違反すると実際にデプロイが失敗し、かつ同じ合成済みテンプレートを見る層が誰も止めない」制約すべて。**候補を落とせるのは下の 2 つのゲートだけ**で、「割に合うか」「L2 が持っているのでは」は判断材料にしない。上流 PR は歓迎だがゲートではなく、ルールは先にここに入る。

## 手順

1. **入力の確定**: 追加したい制約を 1 文で書く（対象リソース型、プロパティ、条件、出典 URL または実際に観測したデプロイエラーメッセージ）。制約がまだ特定できていない（「このサービスで何かルールを増やしたい」段階の）場合は、このスキルではなく `find-preflight-rules` を先に使う。
2. **重複チェック（先にやる）**: 違反最小テンプレートを書き、素のエンジンに直接かける:
   ```bash
   npx ts-node --transpile-only --project test/tsconfig.json scripts/rule-check.ts guard <dir>
   ```
   出力は 1 件 1 行（`BLOCK <file> <ruleId>/<severity>` か `clean <file>`）。
   ERROR/FATAL（source: SCHEMA / CFN_LINT）が既に出るなら**ルールは書かない**。終了し、その旨を報告する。
   判定の全体像（WARN クラスのみ出るがデプロイは失敗するグレーゾーン、L2/cfn-lint/サーバー側検証との棲み分け）は AGENTS.md の「Where this pack sits among validation layers」に従う。L2 (aws-cdk-lib) が同じ検証を持っていても不採用理由にならず、既存ルールの廃止理由にもならない（原則 5）。廃止の引き金は同梱エンジン（か CFN サーバー側検証）がカバーしたときだけで、そのとき重複ガードが自動で赤くなる。
3. **ルール作成**: `rules/<service>/<rule-id>/` に 4 ファイル。規約:
   - `package cdk_preflight` + `import rego.v1`、診断は `make_diag_full("<rule-id>", "ERROR", name, path, msg, fix, url)`
   - ヘルパーは `_pf_<短縮名>_` プレフィックスで一意に
   - `walk` ビルトインは無い。`to_number`/`object.get`/`flatten_list`/`resolve` で明示的に書く
   - fail テンプレートはこのルール**だけ**に違反、pass テンプレートは完全クリーン
   - **数値・長さ・個数の制約は境界ちょうどで書く**。fail は「違反する値のうち限界に最も近いもの」、pass は「限界そのもの」— 20 文字下限なら fail=19 文字 / pass=20 文字であって、fail=5 文字 / pass=26 文字ではない。緩いペアはルールの向きしか証明しない（`count(v) < 20` は fail が 5 文字なら定数が `< 10` でも鳴り、pass が 26 文字なら `< 25` でも黙る）ので、定数も比較演算子も固定できないし、実機ゲートの証拠も弱くなる（19 文字が CREATE に失敗して初めて下限 20 が実証される）。ルールが両端を見ているレンジは fail に両端を置く（fail の判定は「自分のルールの診断が 1 件以上」なので、違反リソースを 2 つ並べてよい）。エンジンのスキーマが既に持っている側の端は入れない — ルールもそこは見ていない（原則 1）し、重複ガードが赤くなる。順序の無い制約（プロパティ欠落、enum の値違い、リソース間の不整合）には境界が無いので対象外
4. **ローカルゲート**: まず `npx ts-node --transpile-only --project test/tsconfig.json scripts/rule-check.ts check <service|rule-id>...` を回す。`rules/` を直接読んで 1 エンジンに全ルールを載せ、fail が自分のルールで鳴るか / pass が全ルール無音か / どちらも組み込みエンジンに止められないかを返す（`bundle-rules` も meta.yaml の evidence も要らないので、実機ゲート前の直しはここで回す。80 本で数秒）。全部 `ok` になってから `npx projen bundle-rules && npx jest test/rules.test.ts test/structure.test.ts`。**jest は `-t` で対象を絞る**。フルスイートは PR 直前の 1 回だけでよく、実測では 401 回中 73 回がフル実行で合計 5.8 時間を溶かしている。
5. **実機再現ゲート**: `bash bench/verify-rule.sh <rule-id>`（要 AWS 認証）。観測したエラーメッセージと日付を `meta.yaml#repro.evidence` に記録。
   - fail テンプレートがデプロイに**成功**したら、それはドキュメント側の誤り（BROKEN-EXPECTATION）。ルールを削除し、証拠を issue に残して終了する。CloudFront では明文化された制約 9 件中 3 件がこれだった（2026-09-02）
   - **予想と違う理由**で失敗した場合（他アカウントの ARN、ドメイン所有権の検証など）は証拠にならない。サービスエラーが対象の制約そのものを名指しするまでテンプレートを作り直すか、除去できない交絡は `evidence` に明記する
   - `doc-only` は「再現に安価に作れないリソース（検証済み ACM 証明書、所有ドメイン等）が要る」場合に限る最終手段であって、まだ試していない制約への近道ではない。詳細は AGENTS.md の "A doc sentence is a hypothesis, not evidence" に従う
6. **仕上げ**: `npx projen build` 全緑 → ブランチ作成 → conventional commit（`feat(rules): add <rule-id>`）→ PR 本文に: 制約の出典 / 重複チェック結果 / 実機再現ログ。

## セッションの切り方（コンテキスト予算）

API コストは **`往復回数 × 平均コンテキスト長`** でほぼ決まる（実測 2026-09-08、全 16 セッション集計: cache_read が入力の 98%、平均 258k tok/往復。平均 372k のセッションはルール 1 本 $5.2、213k で切ったセッションは $1.7）。**1 サービスぶんを 1 セッションで通さない**。`find-preflight-rules` から `candidates.json` を受け取り、下の境界で `/clear` して scratchpad の `<service>/` 配下のファイルだけを引き継ぐ:

| フェーズ | 入口 | 出口 |
|---|---|---|
| ⑤ ルール生成＋ローカルゲート | `candidates.json` | `rules/<service>/*`、`pending.txt`（実機ゲート待ちの rule id） |
| ⑥ 実機ゲート | `pending.txt` | `bench-out/<rule-id>.log`、`meta.yaml#repro.evidence` |
| ⑦ 仕上げ | ⑥ のログ | `pr-body.md` → commit / PR |

守ること:

- **rule.rego と fail/pass テンプレートを 1 本ずつヒアドキュメントで書かない**。`candidates.json` を読むジェネレータ（`rgen.py` 相当）を 1 個置き、直しはジェネレータ側に入れて再生成する。実測では打ち込んだコマンド文字列（2.22 Mtok）が Bash 出力（2.52 Mtok）とほぼ同額で、その **63% が 416 回の 4k 超コマンド**
- **書いたファイルを `cat` で読み返さない**。確認は `scripts/rule-check.ts check` と `npx jest` の結果だけで足りる
- **独立した呼び出しは 1 レスポンスにまとめる**（実測 3,352 往復の 55% がツール 1 個だけ）。`git status` / `log` / `diff` の確認ループも同様で、1,592 回・3.4 時間かかっている
- **実機ゲートは 1 本ずつ対話で回さない**。`pending.txt` を回す 1 スクリプトをバックグラウンドで走らせ、ログは `bench-out/<rule-id>.log` に書かせて、戻すのは 1 行のサマリだけにする。完了待ちのポーリングを 1 往復 1 回やらない（1 往復 ≒ 平均コンテキスト長ぶんの再読み込み）
- ⑤ で候補が数十本あるなら、ジェネレータの入力（`candidates.json`）を直すサイクルに寄せる。個別ルールのデバッグは失敗した数本に絞る
