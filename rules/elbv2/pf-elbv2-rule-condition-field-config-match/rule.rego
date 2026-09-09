package cdk_preflight

import rego.v1

_pf_elbrcc_fix := "Add the *Config that matches Field (or plain Values / RegexValues)"

_pf_elbrcc_url := "https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_RuleCondition.html"

violation contains make_diag_full("pf-elbv2-rule-condition-field-config-match", "ERROR", name,
	sprintf("Properties.Conditions.%d", [c.index]),
	sprintf("For conditions of type '%s', you must specify the following fields: 'Values or RegexValues or %s'", [f, cfg]),
	_pf_elbrcc_fix, _pf_elbrcc_url) if {
	some name in _pf_elb_rules
	some c in _pf_elb_conditions(name)
	f := object.get(c.value, "Field", "")
	cfg := object.get(_pf_elb_cond_config, f, "")
	cfg != ""
	not _pf_elb_ohas(c.value, cfg)
	not _pf_elb_ohas(c.value, "Values")
	not _pf_elb_ohas(c.value, "RegexValues")
}
