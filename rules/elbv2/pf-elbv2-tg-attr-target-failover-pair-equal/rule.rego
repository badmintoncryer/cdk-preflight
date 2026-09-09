package cdk_preflight

import rego.v1

_pf_elbgtfp_fix := "Give target_failover.on_deregistration and target_failover.on_unhealthy the same value"

_pf_elbgtfp_url := "https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_TargetGroupAttribute.html"

_pf_elbgtfp_v(name, k) := v if {
	s := _pf_elb_attrset(name, "TargetGroupAttributes", k)
	count(s) == 1
	some v in s
}

violation contains make_diag_full("pf-elbv2-tg-attr-target-failover-pair-equal", "ERROR", name,
	"Properties.TargetGroupAttributes: target_failover",
	sprintf("target_failover.on_deregistration is '%s' but target_failover.on_unhealthy is '%s'; the service requires the same value for both", [d, u]),
	_pf_elbgtfp_fix, _pf_elbgtfp_url) if {
	some name in _pf_elb_tgs
	d := _pf_elbgtfp_v(name, "target_failover.on_deregistration")
	u := _pf_elbgtfp_v(name, "target_failover.on_unhealthy")
	d != u
}
