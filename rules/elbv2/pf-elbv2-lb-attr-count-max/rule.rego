package cdk_preflight

import rego.v1

_pf_elbacnt_fix := "Keep LoadBalancerAttributes at 20 entries or fewer"

_pf_elbacnt_url := "https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_LoadBalancerAttribute.html"

violation contains make_diag_full("pf-elbv2-lb-attr-count-max", "ERROR", name,
	"Properties.LoadBalancerAttributes",
	sprintf("The load balancer declares %d attributes; ModifyLoadBalancerAttributes accepts at most 20", [n]),
	_pf_elbacnt_fix, _pf_elbacnt_url) if {
	some name in _pf_elb_lbs
	n := count(flatten_list(name, "Properties.LoadBalancerAttributes"))
	n > 20
}
