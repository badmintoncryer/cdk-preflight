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
   - **個数を根拠にするなら数える前にガードを通す**。`flatten_list()` は `Fn::If` を真の枝に潰す（`AWS::NoValue` に落ちる要素まで数える）し、`Ref`/`Fn::Split` を 1 要素で返す。生読みの `count(object.get(...))` はもっと悪く、**オブジェクトに対してキーの数を返す**ので `Fn::If` のマーカーが「3 要素」に化ける。閾値なら `_pf_countable_list(name, path)`、`count(...) > 0` の存在ゲートなら `_pf_unconditional_list(name, path)`、取り出し済みの配列なら `_pf_countable_items(v)`（すべて `rules/_lib/lists.rego`）。`count(...) == 0` の非空検査と `count(...) < N` の下限検査は不要（過大カウントでは鳴らなくなる方向にしか動かない）。**`resolve()` で取った値にガードを足しても無駄**（`Fn::If` はそこに届く前に真の枝へ潰れている）ので、その場合は `is_array()` だけ置く。詳細は AGENTS.md（#258 / #272）
   - fail テンプレートはこのルール**だけ**に違反、pass テンプレートは完全クリーン
   - **数値・長さ・個数の制約は境界ちょうどで書く**。fail は「違反する値のうち限界に最も近いもの」、pass は「限界そのもの」— 20 文字下限なら fail=19 文字 / pass=20 文字であって、fail=5 文字 / pass=26 文字ではない。緩いペアはルールの向きしか証明しない（`count(v) < 20` は fail が 5 文字なら定数が `< 10` でも鳴り、pass が 26 文字なら `< 25` でも黙る）ので、定数も比較演算子も固定できないし、実機ゲートの証拠も弱くなる（19 文字が CREATE に失敗して初めて下限 20 が実証される）。ルールが両端を見ているレンジは fail に両端を置く（fail の判定は「自分のルールの診断が 1 件以上」なので、違反リソースを 2 つ並べてよい）。エンジンのスキーマが既に持っている側の端は入れない — ルールもそこは見ていない（原則 1）し、重複ガードが赤くなる。**しきい値はリテラルでなくてもよい** — 限界が別プロパティの値（`MinValue` と `MaxValue`、コンテナの `Memory` とタスクの `Memory`）なら、fail は 2 つの値を違反側に 1 だけずらし、pass は同値にする（同値で既に違反する `>=` / `<=` は逆で、fail が同値・pass が 1 ずれ）。`MinValue 10 / MaxValue 1` ではルールが `mn > mx + 5` でも鳴るので定数も演算子も固定できない。順序の無い制約（プロパティ欠落、enum の値違い、リソース間の不整合）には境界が無いので対象外
4. **ローカルゲート**: まず `npx ts-node --transpile-only --project test/tsconfig.json scripts/rule-check.ts check <service|rule-id>...` を回す。`rules/` を直接読んで 1 エンジンに全ルールを載せ、fail が自分のルールで鳴るか / pass が全ルール無音か / どちらも組み込みエンジンに止められないかを返す（`bundle-rules` も meta.yaml の evidence も要らないので、実機ゲート前の直しはここで回す。80 本で数秒）。全部 `ok` になってから `npx projen bundle-rules && npx jest test/rules test/structure.test.ts`（`test/rules` は `rules.test.ts` と、ルール表を回す `rules.shard*.test.ts` の両方に当たる）（`bundle-rules` は `src/rules.generated.ts` / `docs/rules.md` に加えて **README のルール数バッジと対応リソースタイプ一覧も書き換える**。手で直さない。古いままなら `structure.test.ts` が落ちる）。**`rules/<service>/` を新設しても `npx projen` は要らない** — `.github/workflows/monthly-verify.yml` のサービス行列は実行時に `scripts/plan-services.py` が `rules/` を読んで組むので workflow ファイル自体は変わらない（#247 で実行時計算へ移行済み。2026-09-26 に `rules/verifiedpermissions/` を新設した PR #286 / #287 でも self-mutation は skipping のままだった）。2026-09-13 に Athena 追加で踏んだのは移行前の話。`structure.test.ts` は手順 3 の境界値を機械で見る（rego のしきい値ごとに fail へ「限界に最も近い違反値」、pass へ「限界そのもの」が現れるか）。しきい値の検出が意味を持たないルールだけ `rules/_boundary-exceptions.txt` に理由付きで逃がす。**jest は `-t` で対象を絞る**。フルスイートは PR 直前の 1 回だけでよく、実測では 401 回中 73 回がフル実行で合計 5.8 時間を溶かしている。
5. **実機再現ゲート**: `bash bench/verify-rule.sh <rule-id>`（要 AWS 認証）。観測したエラーメッセージと日付を `meta.yaml#repro.evidence` に記録。
   - **evidence には実際にデプロイした値を書く**（`bench 2026-09-13 us-east-1: 19-char Value -> "...at least 20 characters" (ROLLBACK_COMPLETE); pass 20-char -> CREATE_COMPLETE`）。境界ちょうどのフィクスチャと組で、限界の位置そのものが meta.yaml から読める
   - fail テンプレートがデプロイに**成功**したら、それはドキュメント側の誤り（BROKEN-EXPECTATION）。ルールを削除し、証拠を issue に残して終了する。CloudFront では明文化された制約 9 件中 3 件がこれだった（2026-09-02）
   - **予想と違う理由**で失敗した場合（他アカウントの ARN、ドメイン所有権の検証など）は証拠にならない。サービスエラーが対象の制約そのものを名指しするまでテンプレートを作り直すか、除去できない交絡は `evidence` に明記する
   - `doc-only` は「再現に安価に作れないリソース（検証済み ACM 証明書、所有ドメイン等）が要る」場合に限る最終手段であって、まだ試していない制約への近道ではない。詳細は AGENTS.md の "A doc sentence is a hypothesis, not evidence" に従う
6. **仕上げ**: `npx projen build` 全緑 → ブランチ作成 → **コミットするのは `rules/**` だけ**（`src/rules.generated.ts` は gitignore 済み、`docs/rules.md` と README のバッジ・リソース表は `bundle-docs` が main で書く。ここを触らないので PR 同士が衝突しない）→ conventional commit（`feat(rules): add <rule-id>`）→ PR 本文に: 制約の出典 / 重複チェック結果 / 実機再現ログ。

## セッションの切り方（コンテキスト予算）

**`run-preflight-issue`（オーケストレーター）経由で走っている場合、⑤⑥⑦ は 1 スライス = 1 サブエージェントが丸ごと持つ。**
`/clear` は要らず、スライスの切り方（20〜25 本・候補 id のプレフィックス境界・同一サービスは直列）と
push / PR の承認待ちはオーケストレーター側の責務。**自分がそのサブエージェントである場合、さらにエージェントを spawn せず、
実機で落ちたルールはその場で削って報告する。** このスキルを人間が直接使うときだけ、下の `/clear` 運用に従う。

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
