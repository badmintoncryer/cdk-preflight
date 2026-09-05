package cdk_preflight

import rego.v1

_pf_wafnu_url := "https://docs.aws.amazon.com/waf/latest/APIReference/API_CreateWebACL.html"

_pf_wafnu_fix := "Give each web ACL / rule group / IP set / regex pattern set a distinct Name within a Scope (or omit Name and let CloudFormation generate one)"

_pf_wafnu_types := {"AWS::WAFv2::WebACL", "AWS::WAFv2::RuleGroup", "AWS::WAFv2::IPSet", "AWS::WAFv2::RegexPatternSet"}

violation contains make_diag_full("pf-wafv2-name-unique", "ERROR", n2, "Properties.Name",
	sprintf("%s already creates a %s named '%s' in scope %s; the second create fails with WAFDuplicateItemException", [n1, t, nm, scope]),
	_pf_wafnu_fix, _pf_wafnu_url) if {
	some t in _pf_wafnu_types
	some n1 in resources_of_type(t)
	some n2 in resources_of_type(t)
	n1 < n2
	nm := resolve(n1, "Properties.Name")
	is_string(nm)
	resolve(n2, "Properties.Name") == nm
	scope := _pf_waflib_scope(n1)
	_pf_waflib_scope(n2) == scope
}
