package cdk_preflight

import rego.v1

_pf_elbrhh_fix := "Write a host name with at least one dot, ending in an alphabetic label"

_pf_elbrhh_url := "https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_RuleCondition.html"

_pf_elbrhh_ok(v) if {
	parts := split(v, ".")
	count(parts) > 1
	regex.match("^[A-Za-z][A-Za-z0-9*?-]*$", parts[count(parts) - 1])
}

violation contains make_diag_full("pf-elbv2-rule-host-header-format", "ERROR", name,
	sprintf("Properties.Conditions.%d", [c.index]),
	sprintf("Condition value '%s' contains a character that is not valid; a host-header value is a host name ending in an alphabetic label", [v]),
	_pf_elbrhh_fix, _pf_elbrhh_url) if {

	some name in _pf_elb_rules
	some c in _pf_elb_conditions(name)
	object.get(c.value, "Field", "") == "host-header"
	some i, v in _pf_elb_cond_values(c.value)
	is_string(v)
	not _pf_elbrhh_ok(v)
}
