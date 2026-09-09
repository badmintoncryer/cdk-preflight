package cdk_preflight

import rego.v1

_pf_elbrhn_fix := "Shorten HttpHeaderName to 40 characters"

_pf_elbrhn_url := "https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_RuleCondition.html"

violation contains make_diag_full("pf-elbv2-rule-http-header-name-length", "ERROR", name,
	sprintf("Properties.Conditions.%d.HttpHeaderConfig.HttpHeaderName", [c.index]),
	sprintf("Condition value for 'http-header' cannot contain more than 40 characters (this one has %d)", [count(h)]),
	_pf_elbrhn_fix, _pf_elbrhn_url) if {
	some name in _pf_elb_rules
	some c in _pf_elb_conditions(name)
	h := _pf_elb_oget(_pf_elb_cond_cfg(c.value), "HttpHeaderName")
	is_string(h)
	count(h) > 40
}
