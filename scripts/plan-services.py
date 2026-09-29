#!/usr/bin/env python3
"""monthly-verify のサービス行列を GITHUB_OUTPUT の 1 行として出す。

リポジトリのルートで実行する:

    python3 scripts/plan-services.py "<service or empty>"   # -> services=[...]
    python3 scripts/plan-services.py --self-test

一覧は **ワークフローの実行時に** `rules/` を読んで組む。以前は projen が
`monthly-verify.yml` に焼き込んでいたが、全サービス名が 1 行に並ぶので、
サービスを足す PR が毎回その同じ行を書き換えて互いに衝突していた
（2026-09-22、#66 の 4 本で踏んだ）。足しても workflow が変わらなければ衝突しない。
"""
import json
import os
import sys

# 1 ジョブに収まらないサービスはジョブを増やす方向にだけ割る（ジョブ内は逐次のままなので
# 同時 VPC 数は maxParallel を超えない）。認証は role-duration-seconds 4h、ジョブは
# timeoutMinutes 300 なので、1 シャード 2h 以内を目安にする。
# まずルール数で割る: 2026-09-29 の初の全件実行（run 36505082526）は 1 本 1〜3.5 分で、
# 割っていなかった batch(183) / appsync(109) / cognito(113) / cloudfront(95) / bedrock(81) が
# 4h を超え、認証が切れた後の残りを ExpiredToken の INCONCLUSIVE で落とした。40 本 × 3 分 = 2h。
PER_SHARD = 40
# ルール数で割っても重いサービスは下で明示する（大きいほうを使う）。
# route53resolver: 実測 2026-09-11 us-east-1（fail-only）— エンドポイントが立ち切る 10 本が
# 337 秒/本、エンドポイント自身が違反で即拒否される 19 本が 225 秒/本、残り 33 本が 50 秒/本。
# 62 本を逐次で回すと 2.6h で、INCONCLUSIVE のリトライが重なると 4h に触れる。3 分割で 1 本 55 分前後。
# msk: 実測 2026-09-13/14 us-east-1 — fail は同期拒否 8 秒 + ROLLBACK 2m51s で 1 本約 3 分、
# うち 13 本は VPC/サブネット/SG を同一スタックに建てるぶん +2 分。52 本を逐次で回すと約 3h で
# 目安の上限に張り付き、INCONCLUSIVE のリトライが乗ると 4h の認証期限に触れる。2 分割で 1 本 1.5h 前後。
# eks: 実測 2026-09-25 us-east-1（fail-only）— fail フィクスチャが自前で EKS クラスタを建てる 39 本が
# 約 16 分/本（クラスタの作成と削除で大半を使う）、CreateCluster が同期で拒否して
# コントロールプレーンが起動しない 32 本が 2〜4 分/本。71 本を逐次で回すと約 12h で、
# 認証の 4h にも timeoutMinutes 300 にも収まらない。シャードの割り当ては上の i % SHARDS
# なので高い本は均等にばらけ、6 分割で 1 シャード 2h 前後になる。
SHARDS = {"route53resolver": 3, "msk": 2, "eks": 6}


def shards(name: str, root: str = "rules") -> int:
    # verify-all.sh と同じく rules/<service>/ 直下のディレクトリを全部数える（doc-only も数えるので多めに割れる）
    count = sum(os.path.isdir(os.path.join(root, name, d)) for d in os.listdir(os.path.join(root, name)))
    return max(SHARDS.get(name, 1), -(-count // PER_SHARD))


def matrix(selection: str, root: str = "rules") -> list:
    out = []
    for name in sorted(os.listdir(root)):
        # rules/_lib は共有ヘルパーでルールではない
        if name.startswith("_") or not os.path.isdir(os.path.join(root, name)):
            continue
        if "." in name:
            # verify-all.sh は "<service>.<i>of<n>" を '.' で切って解釈する
            raise SystemExit(f"service directory name must not contain a dot: {name}")
        n = shards(name, root)
        out += [f"{name}.{i + 1}of{n}" for i in range(n)] if n > 1 else [name]
    if selection:
        # サービス名だけを渡されたらそのサービスのシャードに展開する（知らない名前はそのまま通す）
        out = [s for s in out if s == selection or s.startswith(selection + ".")] or [selection]
    return out


def self_test() -> None:
    every = matrix("")
    # 並びはサービス名の順。文字列としては整列しない（"bedrock.1of3" は "bedrock-agentcore" の後ろに来る）
    assert len(every) == len(set(every)), "重複"
    assert "_lib" not in every, "共有ヘルパーが行列に混ざった"
    for name in sorted({s.split(".")[0] for s in every}):
        n = shards(name)
        parts = [s for s in every if s.startswith(name + ".")]
        count = sum(os.path.isdir(os.path.join("rules", name, d)) for d in os.listdir(os.path.join("rules", name)))
        assert -(-count // n) <= PER_SHARD, f"{name}: {count} 本を {n} シャードでは 1 シャード {PER_SHARD} 本を超える"
        assert n >= SHARDS.get(name, 1), f"{name}: 明示したシャード数より少ない"
        if n > 1:
            assert parts == [f"{name}.{i + 1}of{n}" for i in range(n)], f"{name}: {parts}"
            assert matrix(name) == parts, f"{name} はシャードに展開されるべき"
            assert name not in every, f"{name} はシャードとしてだけ現れるべき"
        else:
            assert parts == [] and name in every, f"{name} は割らずに 1 本で現れるべき"
    one = next(s for s in every if "." not in s)
    assert matrix(one) == [one], f"{one} は自分だけを選ぶべき"
    assert matrix("nosuchservice") == ["nosuchservice"], "知らない名前はそのまま通すべき"
    print(f"ok: {len(every)} matrix entries from rules/")


if __name__ == "__main__":
    arg = sys.argv[1] if len(sys.argv) > 1 else ""
    if arg == "--self-test":
        self_test()
    else:
        print("services=" + json.dumps(matrix(arg)))
