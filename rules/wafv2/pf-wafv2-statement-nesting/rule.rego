package cdk_preflight

import rego.v1

_pf_wafnest_url := "https://docs.aws.amazon.com/waf/latest/developerguide/waf-rule-statements-logical.html"

_pf_wafnest_fix := "Nest at least two statements under AndStatement / OrStatement, and keep ManagedRuleGroupStatement / RuleGroupReferenceStatement / RateBasedStatement at the top of their own rule"

violation contains make_diag_full("pf-wafv2-statement-nesting", "ERROR", name, _pf_waflib_path(i, array.concat(p, [kind, "Statements"])),
	sprintf("%s has %d nested statement(s); at least two are required (the create call fails with \"You haven't met a minimum requirement for a threshold setting\")", [kind, count(sts)]),
	_pf_wafnest_fix, _pf_wafnest_url) if {
	some [name, i, p, kind, body] in _pf_waflib_leaves
	kind in {"AndStatement", "OrStatement"}
	sts := body.Statements
	is_array(sts)
	count(sts) < 2
}

violation contains make_diag_full("pf-wafv2-statement-nesting", "ERROR", name, _pf_waflib_path(i, array.concat(p, [kind])),
	sprintf("%s is nested inside another statement; it can only be a rule's top-level statement (the create call fails with \"A reference in your rule statement is not valid.\")", [kind]),
	_pf_wafnest_fix, _pf_wafnest_url) if {
	some [name, i, p, kind, body] in _pf_waflib_leaves
	count(p) > 0
	kind in {"ManagedRuleGroupStatement", "RuleGroupReferenceStatement", "RateBasedStatement"}
}
