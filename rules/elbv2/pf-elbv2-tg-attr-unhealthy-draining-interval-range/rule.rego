package cdk_preflight

import rego.v1

_pf_elbgudi_fix := "Use a value between 0 and 360000 seconds"

_pf_elbgudi_url := "https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_TargetGroupAttribute.html"

violation contains make_diag_full("pf-elbv2-tg-attr-unhealthy-draining-interval-range", "ERROR", name,
	sprintf("Properties.TargetGroupAttributes.%d.Value", [p.index]),
	sprintf("'%s' is %v, outside the accepted range 0-360000", [p.key, n]),
	_pf_elbgudi_fix, _pf_elbgudi_url) if {
	some name in _pf_elb_tgs
	some p in _pf_elb_pairs(name, "TargetGroupAttributes")
	p.key == "target_health_state.unhealthy.draining_interval_seconds"
	n := _pf_elb_num(p.value)
	_pf_elb_outside(n, 0, 360000)
}
