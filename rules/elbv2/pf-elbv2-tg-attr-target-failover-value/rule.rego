package cdk_preflight

import rego.v1

_pf_elbgtfv_fix := "Use rebalance or no_rebalance"

_pf_elbgtfv_url := "https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_TargetGroupAttribute.html"

violation contains make_diag_full("pf-elbv2-tg-attr-target-failover-value", "ERROR", name,
	sprintf("Properties.TargetGroupAttributes.%d.Value", [p.index]),
	sprintf("'%s' is not a valid value for '%s' (allowed: rebalance, no_rebalance)", [p.value, p.key]),
	_pf_elbgtfv_fix, _pf_elbgtfv_url) if {
	some name in _pf_elb_tgs
	some p in _pf_elb_pairs(name, "TargetGroupAttributes")
	startswith(p.key, "target_failover.")
	is_string(p.value)
	not p.value in {"rebalance", "no_rebalance"}
}
