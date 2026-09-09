package cdk_preflight

import rego.v1

_pf_elbrce_fix := "Put at least one entry in Values (or RegexValues)"

_pf_elbrce_url := "https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_RuleCondition.html"

violation contains make_diag_full("pf-elbv2-rule-condition-empty-values", "ERROR", name,
	sprintf("Properties.Conditions.%d.%s", [c.index, cfg]),
	sprintf("You must provide exactly one of the following: ['Values' 'RegexValues'] for config of type '%s'", [cfg]),
	_pf_elbrce_fix, _pf_elbrce_url) if {
	some name in _pf_elb_rules
	some c in _pf_elb_conditions(name)
	f := object.get(c.value, "Field", "")
	cfg := object.get(_pf_elb_cond_config, f, "")
	_pf_elb_ohas(c.value, cfg)
	count(_pf_elb_cond_values(c.value)) == 0
}
