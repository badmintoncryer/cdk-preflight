package cdk_preflight

import rego.v1

_pf_elbgdfo_fix := "Raise the dns_failover threshold to at least the unhealthy_state_routing one"

_pf_elbgdfo_url := "https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_TargetGroupAttribute.html"

_pf_elbgdfo_n(name, k) := n if {
	s := _pf_elb_attrset(name, "TargetGroupAttributes", k)
	count(s) == 1
	some v in s
	n := _pf_elb_num(v)
}

violation contains make_diag_full("pf-elbv2-tg-attr-dns-failover-threshold-order", "ERROR", name,
	sprintf("Properties.TargetGroupAttributes: target_group_health.dns_failover.minimum_healthy_targets.%s", [unit]),
	sprintf("The DNS failover threshold (%v) is below the unhealthy-state routing threshold (%v); DNS failover must be at least as strict", [d, u]),
	_pf_elbgdfo_fix, _pf_elbgdfo_url) if {
	some name in _pf_elb_tgs
	some unit in ["count", "percentage"]
	d := _pf_elbgdfo_n(name, sprintf("target_group_health.dns_failover.minimum_healthy_targets.%s", [unit]))
	u := _pf_elbgdfo_n(name, sprintf("target_group_health.unhealthy_state_routing.minimum_healthy_targets.%s", [unit]))
	d < u
}
