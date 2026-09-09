package cdk_preflight

import rego.v1

_pf_elbgbv_fix := "Write the value as the string \"true\" or \"false\""

_pf_elbgbv_url := "https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_TargetGroupAttribute.html"

violation contains make_diag_full("pf-elbv2-tg-attr-boolean-value", "ERROR", name,
	sprintf("Properties.TargetGroupAttributes.%d.Value", [p.index]),
	sprintf("The value of '%s' must be 'true' or 'false', but was '%s'", [p.key, p.value]),
	_pf_elbgbv_fix, _pf_elbgbv_url) if {
	some name in _pf_elb_tgs
	some p in _pf_elb_pairs(name, "TargetGroupAttributes")
	_pf_elb_bool_key(p.key)
	p.key != "load_balancing.cross_zone.enabled"
	is_string(p.value)
	not p.value in {"true", "false"}
}
