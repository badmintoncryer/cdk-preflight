package cdk_preflight

import rego.v1

_pf_elbabv_fix := "Write the value as the string \"true\" or \"false\""

_pf_elbabv_url := "https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_LoadBalancerAttribute.html"

violation contains make_diag_full("pf-elbv2-lb-attr-boolean-value", "ERROR", name,
	sprintf("Properties.LoadBalancerAttributes.%d.Value", [p.index]),
	sprintf("The value of '%s' must be 'true' or 'false', but was '%s'", [p.key, p.value]),
	_pf_elbabv_fix, _pf_elbabv_url) if {
	some name in _pf_elb_lbs
	some p in _pf_elb_pairs(name, "LoadBalancerAttributes")
	_pf_elb_bool_key(p.key)
	is_string(p.value)
	not p.value in {"true", "false"}
}
