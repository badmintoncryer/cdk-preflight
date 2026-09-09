package cdk_preflight

import rego.v1

_pf_elbacz_fix := "Leave load_balancing.cross_zone.enabled at true (turn it off per target group instead)"

_pf_elbacz_url := "https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_LoadBalancerAttribute.html"

violation contains make_diag_full("pf-elbv2-lb-attr-alb-cross-zone-immutable", "ERROR", name,
	sprintf("Properties.LoadBalancerAttributes.%d.Value", [p.index]),
	"load_balancing.cross_zone.enabled is 'false' on an application load balancer; the service answers \"The value for 'load_balancing.cross_zone.enabled' must always be 'true' for an Application Load Balancer\"",
	_pf_elbacz_fix, _pf_elbacz_url) if {
	some name in _pf_elb_lbs
	some p in _pf_elb_pairs(name, "LoadBalancerAttributes")
	_pf_elb_lbtype(name) == "application"
	p.key == "load_balancing.cross_zone.enabled"
	p.value == "false"
}
