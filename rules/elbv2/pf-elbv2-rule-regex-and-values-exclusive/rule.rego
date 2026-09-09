package cdk_preflight

import rego.v1

_pf_elbrrv_fix := "Keep Values or RegexValues, not both"

_pf_elbrrv_url := "https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_RuleCondition.html"

violation contains make_diag_full("pf-elbv2-rule-regex-and-values-exclusive", "ERROR", name,
	sprintf("Properties.Conditions.%d.%s", [c.index, cfg]),
	sprintf("You must provide exactly one of the following: ['Values' 'RegexValues'] for config of type '%s'", [cfg]),
	_pf_elbrrv_fix, _pf_elbrrv_url) if {
	some name in _pf_elb_rules
	some c in _pf_elb_conditions(name)
	count(_pf_elb_cond_of(c.value, "Values")) > 0
	count(_pf_elb_cond_of(c.value, "RegexValues")) > 0
	cfg := object.get(_pf_elb_cond_config, object.get(c.value, "Field", ""), "")
}
