package cdk_preflight

import rego.v1

_pf_elbrhm_fix := "Use up to 40 characters of A-Z, - and _ (the service does not case-fold)"

_pf_elbrhm_url := "https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_RuleCondition.html"

violation contains make_diag_full("pf-elbv2-rule-http-method-charset", "ERROR", name,
	sprintf("Properties.Conditions.%d", [c.index]),
	sprintf("Condition value '%s' contains a character that is not valid; an HTTP method is up to 40 characters of A-Z, - and _", [v]),
	_pf_elbrhm_fix, _pf_elbrhm_url) if {

	some name in _pf_elb_rules
	some c in _pf_elb_conditions(name)
	object.get(c.value, "Field", "") == "http-request-method"
	some i, v in _pf_elb_cond_values(c.value)
	is_string(v)
	not regex.match("^[A-Z_-]{1,40}$", v)
}
