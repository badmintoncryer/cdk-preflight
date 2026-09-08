package cdk_preflight

import rego.v1

# RDS ルールの共有ヘルパー。不在の証明は input.resources 側でしかできない
# （resolve() はキー不在と未解決トークンの両方で undefined になる、AGENTS.md 参照）ので、
# 「プロパティが書かれているか」は必ず _pf_rds_has を通す。エンジン名の比較は
# リテラルに限る（Ref はエンジン名ではなく論理 ID に解決されるため）。
# 診断は出さない（BUNDLED_LIBS）。

_pf_rds_props(name) := p if {
	p := input.resources[name].properties
	is_object(p)
}

_pf_rds_get(name, k) := v if {
	v := object.get(_pf_rds_props(name), k, "__pf_absent")
	v != "__pf_absent"
}

_pf_rds_has(name, k) if {
	_pf_rds_get(name, k)
}

# ユーザーが書いたリテラルのエンジン名（小文字）。Ref/GetAtt は論理 ID に解決されるので弾く。
_pf_rds_engine(name) := lower(e) if {
	e := resolve(name, "Properties.Engine")
	is_string(e)
	not input.resources[e]
}

# エンジン系列。互いに前方一致しない接頭辞なので、一致するのは高々 1 つ。
_pf_rds_fam_prefix := {"aurora-mysql", "aurora-postgresql", "mariadb", "mysql", "postgres", "oracle-", "sqlserver-", "db2-"}

_pf_rds_famof(s) := f if {
	is_string(s)
	some f in _pf_rds_fam_prefix
	startswith(lower(s), f)
}

_pf_rds_family(name) := _pf_rds_famof(_pf_rds_engine(name))

_pf_rds_engine_in(name, families) if {
	some f in families
	_pf_rds_family(name) == f
}

# 文書に true と書かれている場合だけ真（未解決トークンは対象外）。
_pf_rds_true(name, k) if _pf_rds_get(name, k) == true

_pf_rds_true(name, k) if _pf_rds_get(name, k) == "true"

_pf_rds_false(name, k) if _pf_rds_get(name, k) == false

_pf_rds_false(name, k) if _pf_rds_get(name, k) == "false"
