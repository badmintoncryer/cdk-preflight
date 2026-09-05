package cdk_preflight

import rego.v1

_pf_wafsl_url := "https://docs.aws.amazon.com/waf/latest/developerguide/limits.html"

_pf_wafsl_fix := "Split the rule (at most 50 country codes per GeoMatchStatement, 50 IP set / regex set / rule group references per web ACL or rule group), shorten query argument names to 30 characters, and de-duplicate IncludedHeaders / ExcludedHeaders / IncludedCookies / ExcludedCookies"

violation contains make_diag_full("pf-wafv2-statement-limits", "ERROR", name, sprintf("%s.CountryCodes", [_pf_waflib_path(i, array.concat(p, ["GeoMatchStatement"]))]),
	sprintf("%d country codes; a geo match statement takes at most 50 (the create call fails with \"Member must have length less than or equal to 50\")", [count(cc)]),
	_pf_wafsl_fix, _pf_wafsl_url) if {
	some [name, i, p, kind, b] in _pf_waflib_leaves
	kind == "GeoMatchStatement"
	cc := b.CountryCodes
	is_array(cc)
	count(cc) > 50
}

violation contains make_diag_full("pf-wafv2-statement-limits", "ERROR", name, sprintf("%s.FieldToMatch.SingleQueryArgument.Name", [_pf_waflib_path(i, array.concat(p, [kind]))]),
	sprintf("query argument name is %d characters; at most 30 are accepted (the create call fails with \"Member must have length less than or equal to 30\")", [count(n)]),
	_pf_wafsl_fix, _pf_wafsl_url) if {
	some [name, i, p, kind, b] in _pf_waflib_leaves
	kind in _pf_waflib_match_keys
	n := b.FieldToMatch.SingleQueryArgument.Name
	is_string(n)
	count(n) > 30
}

violation contains make_diag_full("pf-wafv2-statement-limits", "ERROR", name, sprintf("%s.CustomKeys[%d].QueryArgument.Name", [_pf_waflib_path(i, array.concat(p, ["RateBasedStatement"])), k]),
	sprintf("query argument name is %d characters; at most 30 are accepted (the create call fails with \"Member must have length less than or equal to 30\")", [count(n)]),
	_pf_wafsl_fix, _pf_wafsl_url) if {
	some [name, i, p, kind, b] in _pf_waflib_leaves
	kind == "RateBasedStatement"
	some k
	n := b.CustomKeys[k].QueryArgument.Name
	is_string(n)
	count(n) > 30
}

violation contains make_diag_full("pf-wafv2-statement-limits", "ERROR", name, "Properties.Rules",
	sprintf("%d IP set / regex pattern set / rule group references; at most 50 per web ACL or rule group (the create call fails with WAFLimitsExceededException NUM_REFERENCED_STATEMENT_IN_CONTAINER)", [n]),
	_pf_wafsl_fix, _pf_wafsl_url) if {
	some name in _pf_waflib_containers
	n := count({[i, p, kind] | some [nm, i, p, kind, b] in _pf_waflib_leaves; nm == name; _pf_waflib_ref_kinds[kind]})
	n > 50
}

_pf_wafsl_lists := {"Headers": {"IncludedHeaders", "ExcludedHeaders"}, "Cookies": {"IncludedCookies", "ExcludedCookies"}}

violation contains make_diag_full("pf-wafv2-statement-limits", "ERROR", name, sprintf("%s.FieldToMatch.%s.MatchPattern.%s[%d]", [_pf_waflib_path(i, array.concat(p, [kind])), comp, lk, m]),
	sprintf("'%s' is already listed at [%d]; the create call fails with \"You have duplicated some of the information in the parameter.\"", [l[m], k]),
	_pf_wafsl_fix, _pf_wafsl_url) if {
	some [name, i, p, kind, b] in _pf_waflib_leaves
	kind in _pf_waflib_match_keys
	some comp in object.keys(_pf_wafsl_lists)
	some lk in _pf_wafsl_lists[comp]
	l := b.FieldToMatch[comp].MatchPattern[lk]
	is_array(l)
	some k, m
	k < m
	l[k] == l[m]
}
