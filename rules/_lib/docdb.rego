package cdk_preflight

import rego.v1

# DocumentDB ルールの共有ヘルパー。不在の証明は input.resources 側でしかできない
# （resolve() はキー不在と未解決トークンの両方で undefined になる、AGENTS.md 参照）ので、
# 「プロパティが書かれているか」は必ず _pf_docdb_has を通す。診断は出さない（BUNDLED_LIBS）。

_pf_docdb_props(name) := p if {
	p := input.resources[name].properties
	is_object(p)
}

_pf_docdb_get(name, k) := v if {
	v := object.get(_pf_docdb_props(name), k, "__pf_absent")
	v != "__pf_absent"
}

_pf_docdb_has(name, k) if {
	_pf_docdb_get(name, k)
}

# 文書に true と書かれている場合だけ真（未解決トークンは対象外）。
_pf_docdb_true(name, k) if _pf_docdb_get(name, k) == true

_pf_docdb_true(name, k) if _pf_docdb_get(name, k) == "true"

_pf_docdb_clusters := resources_of_type("AWS::DocDB::DBCluster")

# ユーザーが書いたリテラル文字列。Ref/GetAtt は論理 ID に解決されるので弾く。
_pf_docdb_lit(name, path) := v if {
	v := resolve(name, path)
	is_string(v)
	not input.resources[v]
}

# "HH:MM" -> 分（0-1439）。to_number は先頭ゼロを拒む（to_number("03") は undefined）ので
# 桁表と substring で組む。書式が違えば undefined。
_pf_docdb_digit := {"0": 0, "1": 1, "2": 2, "3": 3, "4": 4, "5": 5, "6": 6, "7": 7, "8": 8, "9": 9}

_pf_docdb_hm(t) := m if {
	is_string(t)
	regex.match(`^([01][0-9]|2[0-3]):[0-5][0-9]$`, t)
	h := (_pf_docdb_digit[substring(t, 0, 1)] * 10) + _pf_docdb_digit[substring(t, 1, 1)]
	mi := (_pf_docdb_digit[substring(t, 3, 1)] * 10) + _pf_docdb_digit[substring(t, 4, 1)]
	m := (h * 60) + mi
}

_pf_docdb_day := {"mon": 0, "tue": 1, "wed": 2, "thu": 3, "fri": 4, "sat": 5, "sun": 6}

# "ddd:HH:MM" -> 週の分（0-10079）。曜日は大小無視。書式が違えば undefined。
_pf_docdb_dhm(t) := m if {
	is_string(t)
	p := split(lower(t), ":")
	count(p) == 3
	d := _pf_docdb_day[p[0]]
	hm := _pf_docdb_hm(sprintf("%s:%s", [p[1], p[2]]))
	m := (d * 1440) + hm
}
