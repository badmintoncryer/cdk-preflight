package cdk_preflight

import rego.v1

_pf_elbrvl_fix := "Shorten the value to 128 characters"

_pf_elbrvl_url := "https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_RuleCondition.html"

violation contains make_diag_full("pf-elbv2-rule-value-length-128", "ERROR", name,
	sprintf("Properties.Conditions.%d", [c.index]),
	sprintf("Condition value for '%s' cannot contain more than 128 characters (this one has %d)", [f, count(v)]),
	_pf_elbrvl_fix, _pf_elbrvl_url) if {
	some name in _pf_elb_rules
	some c in _pf_elb_conditions(name)
	f := object.get(c.value, "Field", "")
	some v in _pf_elb_cond_values(c.value)
	is_string(v)
	count(v) > 128
}
