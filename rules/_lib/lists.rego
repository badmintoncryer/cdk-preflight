package cdk_preflight

import rego.v1

# 「このリストの個数を根拠にしてよいか」を判定するヘルパー。診断は出さない。
#
# flatten_list() は要素数を 2 方向に歪める（#258、2026-09-25 実測）:
#   - Fn::If は真の枝に潰れる。`{"Fn::If": [C, X, {"Ref": "AWS::NoValue"}]}` の要素は
#     C が false ならデプロイ時に消えるのに 1 個として数えられる（過大カウント）
#   - Ref / Fn::Split はリスト全体を 1 要素として返す（過小カウント）
# どちらも「合成済みテンプレートからは実際の個数が分からない」形なので、個数を根拠に
# 診断を出すルールは数える前にここで降りる。
#
# プロパティが無いときは真（flatten_list が [] を返すのと同じく 0 個として数えてよい）。
# path は flatten_list に渡すのと同じ "Properties.A.B" 形式。
_pf_countable_list(name, path) if {
	_pf_ll_raw(name, path) == "__pf_absent"
}

_pf_countable_list(name, path) if {
	_pf_countable_items(_pf_ll_raw(name, path))
}

# path で引けない入れ子（`some s in svcs` の中の配列など）を取り出したあと用。
# `count()` はオブジェクトに対してはキーの数を返すので、Fn::If のマーカーを
# そのまま数えると「3 要素」に化ける。is_array を必ず先に通すこと。
_pf_countable_items(l) if {
	is_array(l)
	count([1 |
		some it in l
		_pf_ll_conditional(it)
	]) == 0
}

# 「このリストの要素はどれもデプロイ時に消えない」: 個数そのものではなく非空だけを
# 根拠にするゲート（`count(...) > 0`）用。Ref / Fn::Split は個数こそ分からないが
# 「在る」ことは確かなので通す。Fn::If が絡んだときだけ降りる。
_pf_unconditional_list(name, path) if {
	l := _pf_ll_raw(name, path)
	not _pf_ll_conditional(l)
	count([1 |
		some it in _pf_ll_elems(l)
		_pf_ll_conditional(it)
	]) == 0
}

# マップのキー数を数えるルール用（`Attributes` のように「リストではなく辞書」で
# 上限が決まるもの）。値が Fn::If でデプロイ時に消えるとキーごと消えるので、
# 条件つきの値が 1 つでもあれば降りる。マーカーそのものを渡されたときも降りる。
_pf_countable_entries(o) if {
	is_object(o)
	not _pf_ll_conditional(o)
	count([1 |
		some _, v in o
		_pf_ll_conditional(v)
	]) == 0
}

# _pf_unconditional_list の値版。生の properties から取り出した値をそのまま数える
# ゲート（`count(object.get(x, "K", [])) > 0`）用。Ref / Fn::Split は個数こそ
# 分からないが「在る」ことは確かなので通し、Fn::If が絡んだときだけ降りる。
_pf_unconditional_items(l) if {
	not _pf_ll_conditional(l)
	count([1 |
		some it in _pf_ll_elems(l)
		_pf_ll_conditional(it)
	]) == 0
}

_pf_ll_elems(l) := l if {
	is_array(l)
}

_pf_ll_elems(l) := [] if {
	not is_array(l)
}

# 生のプロパティ（Ref / Fn::If がマーカーのまま残っている側）を path で引く。
_pf_ll_raw(name, path) := v if {
	segs := split(path, ".")
	v := object.get(object.get(input.resources[name], "properties", {}), array.slice(segs, 1, count(segs)), "__pf_absent")
}

_pf_ll_conditional(it) if {
	is_object(it)
	object.get(it, "__conditional", "__pf_absent") != "__pf_absent"
}
