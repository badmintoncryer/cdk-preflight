package cdk_preflight

import rego.v1

_pf_elbrrf_fix := "Use RegexValues on an http-header, host-header or path-pattern condition"

_pf_elbrrf_url := "https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_RuleCondition.html"

violation contains make_diag_full("pf-elbv2-rule-regex-values-fields", "ERROR", name,
	sprintf("Properties.Conditions.%d.RegexValues", [c.index]),
	sprintf("'RegexValues' is not supported for a condition of type '%s'", [f]),
	_pf_elbrrf_fix, _pf_elbrrf_url) if {
	some name in _pf_elb_rules
	some c in _pf_elb_conditions(name)
	count(_pf_elb_cond_of(c.value, "RegexValues")) > 0
	f := object.get(c.value, "Field", "")
	not f in {"http-header", "host-header", "path-pattern"}
}
