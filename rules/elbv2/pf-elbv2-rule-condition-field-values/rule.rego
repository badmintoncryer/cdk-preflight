package cdk_preflight

import rego.v1

_pf_elbrcf_fix := "Use host-header, path-pattern, http-header, http-request-method, query-string or source-ip"

_pf_elbrcf_url := "https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_RuleCondition.html"

violation contains make_diag_full("pf-elbv2-rule-condition-field-values", "ERROR", name,
	sprintf("Properties.Conditions.%d.Field", [c.index]),
	sprintf("Condition field '%s' must be one of 'http-header,http-request-method,host-header,query-string,source-ip,path-pattern'", [f]),
	_pf_elbrcf_fix, _pf_elbrcf_url) if {
	some name in _pf_elb_rules
	some c in _pf_elb_conditions(name)
	f := _pf_elb_oget(c.value, "Field")
	not f in object.keys(_pf_elb_cond_config)
}
