# 宿題: #66（DocumentDB / Neptune / Redshift / Redshift Serverless）の実機再現ゲート

> **このディレクトリは PR に入れない。** 実機ゲートが終わったら PR を切る前に消す:
> ```bash
> git rm -r bench/pending-66
> ```
> ルール PR が触るのは `rules/**` だけ（AGENTS.md「Adding a rule」手順 5）。

## 現在地（2026-09-22）

`rules/` に **新規 77 本**が入っているが、**実機再現ゲート（`bench/verify-rule.sh`）を 1 本も通していない**。
実装したクラウドセッションに有効な AWS 認証が無かったため（`aws sts get-caller-identity` →
`InvalidClientTokenId`）、ローカルゲートまでで止めてある。**この宿題を終えるまでマージしない。**

| 項目 | 値 |
|---|---|
| ブランチ | `claude/rule-exploration-continued-k82asz` |
| 分岐元 | `origin/main` = `8cd2502` |
| ルール本数 | 77（docdb 18 / docdbelastic 7 / neptune 14 / neptunegraph 3 / redshift 24 / redshiftserverless 11） |
| ローカルゲート | 77/77 `ok`（0 NG）、`jest test/rules test/structure.test.ts` 8 suites / 12907 passed |
| 実機ゲート | **0/77**。全 `meta.yaml` の `repro.evidence` が `bench: PENDING` で終わっている |
| 予算 | 実費上限 **$20**（#66 の着手コメントで宣言済み）。pass 1 本が $1 超なら fail-only |

待ち一覧の確認はいつでもこれで取れる:

```bash
grep -rl 'bench: PENDING' rules/ | xargs -n1 dirname | xargs -n1 basename | sort
```

## 前提（実行環境）

- **AWS 認証**: CloudFormation のスタック作成・削除、および対象 6 サービスの作成権限。`bench/verify-rule.sh`
  は `aws cloudformation create-stack` / `describe-stacks` / `describe-stack-events` / `delete-stack` を使う
- **リージョン**: `us-east-1`（全ルールの `meta.yaml#benchRegion`）。`CDKPF_REGION` で上書きできるが、
  フィクスチャは us-east-1 前提で書かれているので変えない
- **デフォルト VPC が us-east-1 に必要**。多くの pass フィクスチャが `SubnetIds` / `VpcSecurityGroupIds` を
  省略してデフォルト VPC / デフォルト subnet group に頼る。無いと pass が制約と無関係に INCONCLUSIVE になる
- **VPC クォータ**（リージョンあたり 5）: VPC を自作するフィクスチャがある
  （`pf-docdb-subnet-group-*` 2 本 / `pf-neptune-subnet-group-two-az` / `pf-redshiftserverless-workgroup-subnet-az-count` は 1 VPC ずつ、
  `pf-neptunegraph-private-endpoint-subnet-vpc-match` は 2 VPC）。**`run.sh` は直列なので通常は問題ない**が、
  前回の消し残りスタックがあると詰まる。自分で並列化するなら 2 並列まで（2026-09-06 に 8 並列で
  `The maximum number of VPCs has been reached` を踏んでいる）
- **常設の下敷きリソースは不要**（このファミリは #63 CodeSuite や #65 MSK と違い、事前に作っておくものが無い）
- Node 22 / yarn。`npx projen bundle-rules` を 1 回流さないと `src/rules.generated.ts` が無い（gitignore 済み）

## 実行手順

```bash
git clone https://github.com/badmintoncryer/cdk-preflight.git
cd cdk-preflight
git checkout claude/rule-exploration-continued-k82asz
yarn install --frozen-lockfile
npx projen bundle-rules          # src/rules.generated.ts を作る（gitignore 済み）

# ローカルゲートが緑なことを先に確かめる（AWS を使わない、数秒）
npx ts-node --transpile-only --project test/tsconfig.json scripts/rule-check.ts \
  check docdb docdbelastic neptune neptunegraph redshift redshiftserverless

# 実機ゲート（1 本 3〜30 分。全部で数時間かかる。バックグラウンドで流してログだけ見る）
bash bench/pending-66/run.sh "$PWD" bench/pending-66/pending.txt
```

`run.sh` は **1 本ずつ直列**に回す（数時間かかるのでバックグラウンド実行を推奨）。
`bench/pending-66/bench-out/` に `<rule-id>.log` と `summary.tsv` を書き（このディレクトリは git 管理外のまま
捨ててよい）、**exit 0 のルールだけ
`meta.yaml` の `bench: PENDING` を実測行に自動で置き換える**。`summary.tsv` に行があるルールは再実行時にスキップ
されるので、中断しても同じコマンドで再開できる。

### exit code の意味と対応

| rc | 意味 | やること |
|---|---|---|
| 0 | verified（fail が落ち、pass が CREATE_COMPLETE） | 何もしない。`meta.yaml` は自動更新済み |
| 2 | **BROKEN-EXPECTATION**（fail テンプレートがデプロイ成功） | **ルールを削除**（`rm -rf rules/<svc>/<id>`）し、#66 に証拠付きで記録。ドキュメント側の誤り |
| 3 | pass が CREATE_COMPLETE 以外 | フィクスチャの汚れ。pass を直して再実行（`summary.tsv` の該当行を消す） |
| 4 | INCONCLUSIVE（足場が先に倒れた／判定不能） | 下の「交絡」を読み、fixture を直すか `--fail-only` に落とす |

`summary.tsv` の列は `rule / rc / fail の最終ステータス / pass の最終ステータス / fail の理由文`。

## ルール別の注意（実装した 5 エージェントの申し送りを集約）

### fail-only（pass を回さない）— `pending.txt` に印が付いている 5 本

| rule | 理由 |
|---|---|
| `pf-docdbelastic-shard-count-max` | pass = 32 シャード × 2 vCPU = **$8.45/hr** |
| `pf-docdbelastic-shard-instance-count-max` | pass = 16 インスタンス × 2 vCPU = **$4.22/hr** |
| `pf-redshift-node-type-single-node-support` | pass = ra3.4xlarge × 2 = **$6.5/hr** |
| `pf-docdb-restore-copy-on-write-time` | コストではなく再現性。作りたてのクラスタは `LatestRestorableTime` が未確定で pass が制約と無関係に落ちる |
| `pf-docdb-restore-time-exclusive` | 同上 |

fail-only にした理由は `meta.yaml#repro.evidence` に自動で `pass: fail-only (see #66)` として残る。

### pass を回すか判断がいる 9 本（`pending.txt` の行末に ` fail-only` を足せば落とせる）

予算 $20 に対する見積りは全部回して **$5〜10**。境界値の証拠（pass = 限界そのもの）が強くなるので、
予算が許すなら回す方がよい（AGENTS.md 原則 2）。

- `pf-redshift-port-range-ra3` — pass はクラスタ 4 つ同時（$2.2/hr、15 分で約 $0.55）
- `pf-redshift-multi-node-min-nodes` — pass が 2 ノード（約 $1.09/hr）
- `pf-neptunegraph-vector-dimension-range` — pass はグラフ 2 つ（約 $0.5）。**65536 次元が 16 m-NCU で建つか未確認**。建たなければ fail-only へ
- Redshift Serverless の Workgroup 系 6 本 — `base-capacity-floor` / `base-capacity-step` /
  `max-capacity-ge-base` / `port-range` / `price-performance-level-enum` / `workgroup-subnet-az-count`。
  **Workgroup がアイドルで RPU 課金されるかが未確定**。課金されるなら 6 本とも fail-only

`AWS::NeptuneGraph::Graph` は **$0.03/m-NCU-hr**（フィクスチャは 16 m-NCU / ReplicaCount 0 = $0.48/hr/graph）。
NeptuneGraph 3 本は B フェーズで `create-*` を一度も呼んでいないので、**実機が初回の実測**になる。

### post-create（fail でも親リソースが建ってから落ちる。1 本 10〜15 分、数十セント）

`pf-docdb-instance-az-region` / `pf-neptune-db-serverless-needs-scaling-config` / `pf-neptune-instance-az-region` /
`pf-redshift-defer-maintenance-duration-endtime` / `pf-redshift-defer-maintenance-duration-max` /
`pf-redshift-scheduled-action-schedule-format` / `pf-redshift-scheduled-action-start-before-end` /
`pf-neptunegraph-private-endpoint-subnet-vpc-match` / `pf-redshiftserverless-snapshot-copy-destination-region-self`

### BROKEN の可能性が高い（rc=2 なら削除して #66 に記録）

- `pf-redshift-defer-maintenance-duration-endtime` / `-max` — CFN ハンドラが `DeferMaintenance: true` で
  `ModifyClusterMaintenance` を呼ばない可能性がある。呼ばなければ fail が CREATE_COMPLETE になる
- `pf-neptunegraph-graph-name-lowercase` — 同梱スキーマのパターンが大文字を通す（重複ガードは clean）。
  API モデル（botocore の `(?!g-)[a-z][a-z0-9]*(-[a-z0-9]+)*`）は小文字限定なので低リスクだが、通ったらグラフが 1 つ建つ
- `pf-docdb-restore-copy-on-write-time` / `pf-docdb-restore-time-exclusive` — ハンドラが復元プロパティを
  黙って捨てるなら CREATE_COMPLETE になる（#79 RDS で同型の事例あり）

### 交絡（この文面が出たら証拠にしない。fixture を直す）

| rule | 交絡する文面 | 対処 |
|---|---|---|
| `pf-redshift-scheduled-action-*` 2 本 | `IamRole` / `ClusterNotFound` を名指し | fixture の IAM ロール信頼ポリシー（`scheduler.redshift.amazonaws.com`）と `Ref` を直す |
| `pf-redshift-elastic-ip-vs-az-relocation` | `single-node Multi-AZ` / subnet group を名指し | 期待は "Don't specify the Elastic IP…" 相当 |
| `pf-docdb-restore-*` 2 本 | `before earliest restorable time` | `RestoreToTime` を当日に寄せる |
| `pf-docdb-storage-type-engine-version` | `engine version not found` | fail の `EngineVersion: 4.0.0` が EOL の可能性（3.6.0 も EOL）。現存版に差し替え |
| `pf-neptune-cpg-family-engine-version` | 同上 | `EngineVersion: 1.3.4.0` 固定。`aws neptune describe-db-engine-versions` の現存版に差し替えて再生成 |
| `pf-redshiftserverless-default-iam-role-in-iam-roles` | `Invalid IAM role`（IAM 伝播遅延） | そのまま再実行 |
| `pf-redshiftserverless-admin-secret-kms-requires-manage` | pass だけ落ちる | pass の `alias/aws/secretsmanager` 指定をキーごと外す |
| `pf-redshift-master-password-secret-kms-requires-manage` | 同上 | 同上 |
| `pf-redshiftserverless-workgroup-subnet-az-count` | 空き IP 数と AZ 数が混ざる | サブネットは /24 なので IP 側は充足。EVR=true + 3AZ の pass が CREATE_COMPLETE なら確定 |

### deploy_region 依存（4 本）

`pf-docdb-instance-az-region` / `pf-neptune-instance-az-region` / `pf-redshift-availability-zone-region` /
`pf-redshiftserverless-snapshot-copy-destination-region-self` は enforce プラグインが `deploy_region` を
注入したときだけ鳴る（warn モードやリージョン未指定アプリでは無音）。`meta.yaml#repro.evidence` に明記済み。
`pf-redshift-availability-zone-region` の fail は UNNAMED メッセージ
`Cluster subnet group default doesn't cover the AZ specified.` が返る想定。

### 境界が片端しか実測されていない 4 本（実機で逆側を確かめ、ずれていたら定数を直して再生成）

| rule | 状況 |
|---|---|
| `pf-docdbelastic-admin-password-length` | B は 7 文字で拒否を観測。下限が 8 か 9 かは pass の 8 文字クラスタで確定。落ちたら rego を `< 8` → `< 9` に |
| `pf-redshift-defer-maintenance-duration-max` | botocore 1.43.62 は 60、旧 doc は 45。実機が 45 なら定数を 46/45 に |
| `pf-redshift-scheduled-action-start-before-end` | 同値（start == end）が未実測。現状 `>=` で判定 |
| `pf-redshiftserverless-base-capacity-step` | fail は 9（境界に最も近い違反値）。B は 12 で観測 |

### `--fail-only` の連鎖フィクスチャについて

`pf-docdbelastic-*` の fail テンプレートは違反リソースを 2 つ `DependsOn` で連鎖させてある（1 本目が落ちるので
2 本目は実機では試されない）。これは `rules/memorydb` と同じ運用で、`meta.yaml#repro.evidence` にその旨を書く。

## 実機ゲートが終わったら

1. **BROKEN（rc=2）を削除**し、#66 に「何本が BROKEN で落ちたか」を証拠付きでコメントする
   （このプロジェクトでは落選理由を残すことが成果物。次の担当が同じ調査を繰り返さないため）
2. `grep -rl 'bench: PENDING' rules/` が**空になる**ことを確認する
3. 再ビルドと全テスト:
   ```bash
   npx projen bundle-rules
   npx jest test/rules test/structure.test.ts
   npx projen build          # PR 直前に 1 回
   ```
4. **このディレクトリを消す**: `git rm -r bench/pending-66`
5. **PR を 4 本**に切る（サービス単位。`rules/_lib/*.rego` は対応するサービスの PR に入れる）:

   | PR | 含めるもの |
   |---|---|
   | 1 | `rules/docdb/**` + `rules/docdbelastic/**` + `rules/_lib/docdb.rego` + **`.github/workflows/monthly-verify.yml`** |
   | 2 | `rules/neptune/**` + `rules/neptunegraph/**` + `rules/_lib/neptune.rego` |
   | 3 | `rules/redshift/**` + `rules/_lib/redshift.rego` |
   | 4 | `rules/redshiftserverless/**` + `rules/_lib/redshiftserverless.rego` |

   `rules/_boundary-exceptions.txt` は 3 本（docdb / neptune / redshiftserverless）が 1 行ずつ足しているので、
   それぞれの PR に自分の行だけを入れる。`monthly-verify.yml` の行列（6 サービス追加）は**最初の PR にだけ**
   載せる — 新しい `rules/<service>/` を足すと `npx projen` が書き換えるので、入れないと self-mutation が赤くなる
   （2026-09-13、Athena 追加で踏んだ）
6. PR 本文には制約の出典 / 重複ガード結果 / 実機再現ログを書く（AGENTS.md 手順 6）
7. 全部マージされたら **#66 に結果コメントを残して close** し、**#91 のチェックを付けて** 1 行サマリを書き、
   ルールにできなかった分を #91 の「積み残し」に移す

## 未解決の判断（人間に投げてある 8 件）

1. 実機ゲートを回す環境（= この宿題）
2. fail-only 推奨 9 本の pass を回すか
3. `pf-neptunegraph-graph-name-lowercase` に API モデル由来の **`g-` 接頭辞禁止**を第 2 分岐として同梱した
   （A の候補文には無い制約）。id と合わなければ外すか別 id に
4. `pf-ddb-vpc-security-groups-max` の復活可否 — DocDB の 5 が EC2 の「ENI あたり SG」クォータ（引き上げ可）と
   独立な硬い上限だと確認できれば実装可（fail 6 SG / pass 5 SG は無料）。AGENTS.md 原則 6 の判定が要る
5. Redshift の追加候補 2 件（A のリスト外、未実装）:
   (a) `NodeType dc2.* / ds2.*` は注文不可（レンズ 6、B に実測メッセージあり）
   (b) `MultiAZ` は 2 ノード以上必須（doc 明文、fail が single-node で無料）
6. `rules/_lib/rds.rego#_pf_rds_has` に潜在バグ — literal `false` を「不在」と判定する。Neptune の `_has` で
   同型のバグを踏んで修正済み。現行の rds 呼び出しでは実害が無さそうだが要 issue
7. `pf-redshiftserverless-log-exports-enum` はグレーゾーン（エンジンが `W3030` 止まり）のつなぎとして
   `upstream: pending-engine` で同梱。上流に severity issue を出すか
8. `pf-rss-config-parameter-key-enum` の復活 — B の許容キー一覧が issue コメント上で `wlm_js` で途中切れ。
   `aws redshift-serverless create-workgroup --config-parameters parameterKey=zzz,parameterValue=1`
   を 1 回空打ちすれば全文が取れる（拒否されるだけなので無課金）。取れたら `gen/gen-redshiftserverless.py`
   に 1 ルール足して再生成できる

## 参照

- issue **#66** — [C フェーズ結果コメント](https://github.com/badmintoncryer/cdk-preflight/issues/66#issuecomment-5772223651)（落選 14 件の理由、fail-only、交絡、この宿題の要約）
- issue **#66** — [handoff.md 全文](https://github.com/badmintoncryer/cdk-preflight/issues/66#issuecomment-5772259101)（候補 id → rule id の対応表、スライスごとの詳細）
- issue **#66** — A 棚卸し（候補 106 本）と B API 一次選別（TARGET 63 / UNNAMED 4 / BROKEN 1 / BENCH 19 / HOLD 4 / DROP 4）のコメント
- issue **#91** — rule discovery queue
- `AGENTS.md` —「Adding a rule (the pipeline)」「Rule lifecycle」「Known engine facts」
- `.claude/skills/add-preflight-rule/` — 手順 5（実機ゲート）と 6（仕上げ）

## このディレクトリの中身

| ファイル | 中身 |
|---|---|
| `README.md` | これ |
| `pending.txt` | 実機ゲート待ち 77 本。1 行 1 rule id、行末の `fail-only` で pass を飛ばす |
| `run.sh` | 一括ランナー。`bash run.sh <repo-dir> <pending.txt> [--fail-only]` |
| `gen/gen-*.py` | 各スライスのルール生成器。`rule.rego` / fail / pass / `meta.yaml` を吐く。定数を直して再生成するときに使う（`--list` で候補 id → rule id の対応表が出るものもある） |
