package cdk_preflight

import rego.v1

_pf_elbrsc_fix := "Write the address as a CIDR block (10.0.0.1/32 for a single address)"

_pf_elbrsc_url := "https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_RuleCondition.html"

_pf_elbrsc_ok(v) if regex.match(`^[0-9]{1,3}(\.[0-9]{1,3}){3}/[0-9]{1,2}$`, v)

_pf_elbrsc_ok(v) if regex.match(`^[0-9A-Fa-f:]+/[0-9]{1,3}$`, v)

violation contains make_diag_full("pf-elbv2-rule-source-ip-cidr", "ERROR", name,
	sprintf("Properties.Conditions.%d", [c.index]),
	sprintf("The specified value '%s' is not a valid CIDR block", [v]),
	_pf_elbrsc_fix, _pf_elbrsc_url) if {

	some name in _pf_elb_rules
	some c in _pf_elb_conditions(name)
	object.get(c.value, "Field", "") == "source-ip"
	some i, v in _pf_elb_cond_values(c.value)
	is_string(v)
	not _pf_elbrsc_ok(v)
}
