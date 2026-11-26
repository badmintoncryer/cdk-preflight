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

# 参照と組み込み関数（誤検知の根絶: 参照をリテラルと読む）。
# resolve() は Ref / Fn::GetAtt を参照先の論理 ID（文字列）に解決し、解決できない組み込み関数は
# マーカー（オブジェクト）にするか未定義にする。どれもデプロイまで値が分からない。
# 「X ではない」「Y を含まない」と否定で判定するルールは、値が確定しているときだけ鳴らすこと:
# 確定値は _pf_lit、書かれているが読めない値は _pf_unknown で判定する。
# scripts/reference-sweep.ts が、各ルールの pass テンプレートの文字列を参照に替えて確かめる。

# resolve() した値が確定値（論理 ID でない文字列、数値、真偽値）。
_pf_is_lit(v) if {
	is_string(v)
	not input.resources[v]
}

_pf_is_lit(v) if is_number(v)

_pf_is_lit(v) if is_boolean(v)

# path（"Properties.A.0.B"）の確定値。
_pf_lit(name, path) := v if {
	v := resolve(name, path)
	_pf_is_lit(v)
}

# path にテンプレートが値を書いているが、確定値として読めない（参照・組み込み関数）。
_pf_unknown(name, path) if {
	_pf_raw_present(name, path)
	not _pf_has_lit(name, path)
	not _pf_lit_container(name, path)
}

# false の確定値でも成り立つように、値ではなく定義されていることを見る。
_pf_has_lit(name, path) if {
	_ := _pf_lit(name, path)
}

# 配列やオブジェクトは確定値の判定対象外（要素ごとに判定する）。
_pf_lit_container(name, path) if {
	v := resolve(name, path)
	is_array(v)
}

_pf_lit_container(name, path) if {
	v := resolve(name, path)
	is_object(v)
	not _pf_marker(v)
}

_pf_marker(v) if v.__ref

_pf_marker(v) if v.__dynamic

_pf_raw_present(name, path) if {
	parts := split(path, ".")
	parts[0] == "Properties"
	keys := [k | some i, s in parts; i > 0; k := _pf_path_key(s)]
	object.get(input.resources[name].properties, keys, "__pf_absent") != "__pf_absent"
}

_pf_path_key(s) := to_number(s) if regex.match(`^[0-9]+$`, s)

_pf_path_key(s) := s if not regex.match(`^[0-9]+$`, s)

# path のリスト自体、またはその要素のどれかが確定値として読めない。
_pf_list_unknown(name, path) if _pf_unknown(name, path)

_pf_list_unknown(name, path) if {
	some it in flatten_list(name, path)
	_pf_unknown(name, sprintf("%s.%d", [path, it.index]))
}

# JSON にしたときの長さの下限。読めない値（マーカー）は "" として数える（デプロイ時にはそれより長い）。
# サイズ上限のルールは、参照の値の長さを推し量らずにこの下限で判定する。
_pf_json_size_min(doc) := n if {
	s := json.marshal(doc)
	markers := regex.find_n(`\{"__[a-z_]+":(?:"(?:[^"\\]|\\.)*"|[^{}"])*\}`, s, -1)
	n := count(s) - sum([x | some m in markers; x := count(m) - 2])
}

# オブジェクト o のキー k の値。キーが無ければ未定義（object.get の既定値の代わり）。
# 省略を「サービスの既定値が指定された」と読まずに、その判定ごと降りる。
# k はキー 1 つか、object.get と同じキーの配列（入れ子のパス）。
_pf_oval(o, k) := o[k] if {
	is_object(o)
	not is_array(k)
}

_pf_oval(o, k) := v if {
	is_object(o)
	is_array(k)
	v := object.get(o, k, "__pf_absent")
	v != "__pf_absent"
}
