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
# timeoutMinutes 300 なので、1 シャード 3h 以内を目安にする。
# route53resolver: 実測 2026-09-11 us-east-1（fail-only）— エンドポイントが立ち切る 10 本が
# 337 秒/本、エンドポイント自身が違反で即拒否される 19 本が 225 秒/本、残り 33 本が 50 秒/本。
# 62 本を逐次で回すと 2.6h で、INCONCLUSIVE のリトライが重なると 4h に触れる。3 分割で 1 本 55 分前後。
# msk: 実測 2026-09-13/14 us-east-1 — fail は同期拒否 8 秒 + ROLLBACK 2m51s で 1 本約 3 分、
# うち 13 本は VPC/サブネット/SG を同一スタックに建てるぶん +2 分。52 本を逐次で回すと約 3h で
# 目安の上限に張り付き、INCONCLUSIVE のリトライが乗ると 4h の認証期限に触れる。2 分割で 1 本 1.5h 前後。
SHARDS = {"route53resolver": 3, "msk": 2}


def matrix(selection: str, root: str = "rules") -> list:
    out = []
    for name in sorted(os.listdir(root)):
        # rules/_lib は共有ヘルパーでルールではない
        if name.startswith("_") or not os.path.isdir(os.path.join(root, name)):
            continue
        if "." in name:
            # verify-all.sh は "<service>.<i>of<n>" を '.' で切って解釈する
            raise SystemExit(f"service directory name must not contain a dot: {name}")
        n = SHARDS.get(name)
        out += [f"{name}.{i + 1}of{n}" for i in range(n)] if n else [name]
    if selection:
        # サービス名だけを渡されたらそのサービスのシャードに展開する（知らない名前はそのまま通す）
        out = [s for s in out if s == selection or s.startswith(selection + ".")] or [selection]
    return out


def self_test() -> None:
    every = matrix("")
    assert every == sorted(set(every)), "重複か未ソート"
    assert "_lib" not in every, "共有ヘルパーが行列に混ざった"
    for name, n in SHARDS.items():
        shards = [s for s in every if s.startswith(name + ".")]
        assert shards == [f"{name}.{i + 1}of{n}" for i in range(n)], f"{name}: {shards}"
        assert matrix(name) == shards, f"{name} はシャードに展開されるべき"
        assert name not in every, f"{name} はシャードとしてだけ現れるべき"
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
