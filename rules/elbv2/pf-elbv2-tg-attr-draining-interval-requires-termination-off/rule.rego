package cdk_preflight

import rego.v1

_pf_elbgdit_fix := "Set target_health_state.unhealthy.connection_termination.enabled to false, or drop the draining interval"

_pf_elbgdit_url := "https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_TargetGroupAttribute.html"

violation contains make_diag_full("pf-elbv2-tg-attr-draining-interval-requires-termination-off", "ERROR", name,
	sprintf("Properties.TargetGroupAttributes.%d.Value", [p.index]),
	"target_health_state.unhealthy.draining_interval_seconds is set while target_health_state.unhealthy.connection_termination.enabled is 'true'; a connection that is terminated has nothing to drain",
	_pf_elbgdit_fix, _pf_elbgdit_url) if {
	some name in _pf_elb_tgs
	some p in _pf_elb_pairs(name, "TargetGroupAttributes")
	p.key == "target_health_state.unhealthy.draining_interval_seconds"
	"true" in _pf_elb_attrset(name, "TargetGroupAttributes", "target_health_state.unhealthy.connection_termination.enabled")
}
