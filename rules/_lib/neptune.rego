package cdk_preflight

import rego.v1

# Neptune / Neptune Analytics ルールの共有ヘルパー。診断は出さない（BUNDLED_LIBS）。
# 不在の証明は input.resources 側でしかできない（resolve() はキー不在と未解決トークンの
# 両方で undefined、AGENTS.md 参照）ので、「書かれているか」は _pf_neptunelib_has を通す。

_pf_neptunelib_props(name) := p if {
	p := input.resources[name].properties
	is_object(p)
}

_pf_neptunelib_get(name, k) := v if {
	v := object.get(_pf_neptunelib_props(name), k, "__pf_absent")
	v != "__pf_absent"
}

# 値が false のキーも「書かれている」。素の関数呼び出しを文にすると戻り値 false で
# 本体が失敗する（2026-09-22 実測: StorageEncrypted: false が「不在」に見えた）ので比較で書く。
_pf_neptunelib_has(name, k) if {
	object.get(_pf_neptunelib_props(name), k, "__pf_absent") != "__pf_absent"
}

# 文書に true / false と書かれている場合だけ真（未解決トークンはどちらでもない）。
_pf_neptunelib_true(name, k) if _pf_neptunelib_get(name, k) == true

_pf_neptunelib_true(name, k) if _pf_neptunelib_get(name, k) == "true"

_pf_neptunelib_false(name, k) if _pf_neptunelib_get(name, k) == false

_pf_neptunelib_false(name, k) if _pf_neptunelib_get(name, k) == "false"

# "hh:mm" -> 分。to_number は先頭ゼロを受けない（AGENTS.md）ので桁表で組む。
_pf_neptunelib_digit := {"0": 0, "1": 1, "2": 2, "3": 3, "4": 4, "5": 5, "6": 6, "7": 7, "8": 8, "9": 9}

_pf_neptunelib_hhmm(t) := m if {
	is_string(t)
	regex.match(`^([01][0-9]|2[0-3]):[0-5][0-9]$`, t)
	h := (_pf_neptunelib_digit[substring(t, 0, 1)] * 10) + _pf_neptunelib_digit[substring(t, 1, 1)]
	mi := (_pf_neptunelib_digit[substring(t, 3, 1)] * 10) + _pf_neptunelib_digit[substring(t, 4, 1)]
	m := (h * 60) + mi
}

# "hh:mm-hh:mm"（バックアップ窓）の始点 / 終点（分）。書式外は undefined。
_pf_neptunelib_wstart(w) := m if {
	is_string(w)
	p := split(w, "-")
	count(p) == 2
	m := _pf_neptunelib_hhmm(p[0])
}

_pf_neptunelib_wend(w) := m if {
	is_string(w)
	p := split(w, "-")
	count(p) == 2
	m := _pf_neptunelib_hhmm(p[1])
}

# "ddd:hh:mm"（メンテナンス窓の片側）-> 月曜 00:00 からの分。
_pf_neptunelib_day := {"mon": 0, "tue": 1, "wed": 2, "thu": 3, "fri": 4, "sat": 5, "sun": 6}

_pf_neptunelib_wkmin(t) := m if {
	is_string(t)
	p := split(lower(t), ":")
	count(p) == 3
	d := _pf_neptunelib_day[p[0]]
	hm := _pf_neptunelib_hhmm(sprintf("%s:%s", [p[1], p[2]]))
	m := (d * 1440) + hm
}
