package cdk_preflight

import rego.v1

_pf_wafeo_url := "https://docs.aws.amazon.com/waf/latest/APIReference/API_Statement.html"

_pf_wafeo_fix := "Keep exactly one key in each Statement / FieldToMatch / MatchPattern / CustomKeys[] object; combine alternatives with AndStatement / OrStatement or separate rules"

_pf_wafeo_msg(what, n) := sprintf("%s names %d alternatives; the create call fails with \"EXACTLY_ONE_CONDITION_REQUIRED\"", [what, n])

violation contains make_diag_full("pf-wafv2-statement-exactly-one", "ERROR", name, _pf_waflib_path(i, p),
	_pf_wafeo_msg("Statement", count(object.keys(s))), _pf_wafeo_fix, _pf_wafeo_url) if {
	some [name, i, p, s] in _pf_waflib_stmts
	count(object.keys(s)) != 1
}

violation contains make_diag_full("pf-wafv2-statement-exactly-one", "ERROR", name, _pf_waflib_path(i, array.concat(p, [kind, "FieldToMatch"])),
	_pf_wafeo_msg("FieldToMatch", count(object.keys(f))), _pf_wafeo_fix, _pf_wafeo_url) if {
	some [name, i, p, kind, body] in _pf_waflib_leaves
	kind in _pf_waflib_match_keys
	f := body.FieldToMatch
	is_object(f)
	count(object.keys(f)) != 1
}

violation contains make_diag_full("pf-wafv2-statement-exactly-one", "ERROR", name, _pf_waflib_path(i, array.concat(p, [kind, "FieldToMatch", comp, "MatchPattern"])),
	_pf_wafeo_msg(sprintf("%s.MatchPattern", [comp]), count(object.keys(mp))), _pf_wafeo_fix, _pf_wafeo_url) if {
	some [name, i, p, kind, body] in _pf_waflib_leaves
	kind in _pf_waflib_match_keys
	some comp in {"JsonBody", "Headers", "Cookies"}
	mp := body.FieldToMatch[comp].MatchPattern
	is_object(mp)
	count(object.keys(mp)) != 1
}

violation contains make_diag_full("pf-wafv2-statement-exactly-one", "ERROR", name, _pf_waflib_path(i, array.concat(p, ["RateBasedStatement", "CustomKeys", k])),
	_pf_wafeo_msg("custom key", count(object.keys(ck))), _pf_wafeo_fix, _pf_wafeo_url) if {
	some [name, i, p, kind, body] in _pf_waflib_leaves
	kind == "RateBasedStatement"
	some k
	ck := body.CustomKeys[k]
	is_object(ck)
	count(object.keys(ck)) != 1
}
