package cdk_preflight

import rego.v1

# 値の読み方の共通層。「確信が持てないときは黙る」をルールの書き手ではなくここで保証する。
#
# テンプレートの値は 3 つのどれか: 確定値（書かれていて読める）、省略（キーが無い）、
# 不明（組み込み関数のマーカー、解決できない Ref、Fn::If が AWS::NoValue に潰れた null）。
# 比較してよいのは確定値だけで、省略と不明では未定義（＝ルールが降りる）にする。
#
# 省略を「サービスの既定値」と読みたいときは、object.get の既定値に書き込まず、
# 既定値をここ（または service の lib）に出典付きで置くこと。scripts/lint-rules.ts が
# 新しいインライン既定値を弾く。

# 数値として読む。ルールは to_number を直接呼ばない（scripts/lint-rules.ts が弾く）。
# to_number は null を 0、真偽値を 0 / 1 にする（#392 / #396: 省略した Memory が 0 と
# 読まれた）。ここではどちらも未定義にし、マーカー（オブジェクト）や配列も降りる。
# 数値でない文字列は to_number 自体が未定義なので、そのまま降りる。
_pf_tonum(v) := n if {
	v != null
	not is_boolean(v)
	not is_object(v)
	not is_array(v)
	n := to_number(v)
}

# オブジェクト o のキー k を数値として読む。キーが無ければ未定義。
# `to_number(object.get(o, k, null))` の置き換え。
_pf_onum(o, k) := _pf_tonum(o[k]) if is_object(o)
