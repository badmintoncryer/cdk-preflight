package cdk_preflight

import rego.v1

_pf_elbacka_fix := "Use a value between 60 and 604800 seconds"

_pf_elbacka_url := "https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_LoadBalancerAttribute.html"

violation contains make_diag_full("pf-elbv2-lb-attr-client-keep-alive-range", "ERROR", name,
	sprintf("Properties.LoadBalancerAttributes.%d.Value", [p.index]),
	sprintf("'%s' is %v, outside the accepted range 60-604800", [p.key, n]),
	_pf_elbacka_fix, _pf_elbacka_url) if {
	some name in _pf_elb_lbs
	some p in _pf_elb_pairs(name, "LoadBalancerAttributes")
	p.key == "client_keep_alive.seconds"
	n := _pf_elb_num(p.value)
	_pf_elb_outside(n, 60, 604800)
}
