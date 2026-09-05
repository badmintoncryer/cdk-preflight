package cdk_preflight

import rego.v1

_pf_wafru_url := "https://docs.aws.amazon.com/waf/latest/APIReference/API_Rule.html"

_pf_wafru_fix := "Give every rule in Rules[] a distinct Priority and a distinct Name"

violation contains make_diag_full("pf-wafv2-rule-unique", "ERROR", name, sprintf("Properties.Rules[%d].Priority", [j]),
	sprintf("priority %d is also used by rule '%s' (Rules[%d]); the create call fails with \"You have a duplicate priority. Priorities must be unique.\"", [pr, rules[i].Name, i]),
	_pf_wafru_fix, _pf_wafru_url) if {
	some name in _pf_waflib_containers
	rules := _pf_waflib_rules(name)
	some i, j
	i < j
	pr := rules[i].Priority
	is_number(pr)
	rules[j].Priority == pr
}

violation contains make_diag_full("pf-wafv2-rule-unique", "ERROR", name, sprintf("Properties.Rules[%d].Name", [j]),
	sprintf("rule name '%s' is also used by Rules[%d]; the create call fails with \"You have duplicated some of the information in the parameter.\"", [nm, i]),
	_pf_wafru_fix, _pf_wafru_url) if {
	some name in _pf_waflib_containers
	rules := _pf_waflib_rules(name)
	some i, j
	i < j
	nm := rules[i].Name
	is_string(nm)
	rules[j].Name == nm
}
