package cdk_preflight

import rego.v1

_pf_elbasip_fix := "Use a value between 0 and 7"

_pf_elbasip_url := "https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_LoadBalancerAttribute.html"

violation contains make_diag_full("pf-elbv2-lb-attr-secondary-ips-range", "ERROR", name,
	sprintf("Properties.LoadBalancerAttributes.%d.Value", [p.index]),
	sprintf("'%s' is %v, outside the accepted range 0-7", [p.key, n]),
	_pf_elbasip_fix, _pf_elbasip_url) if {
	some name in _pf_elb_lbs
	some p in _pf_elb_pairs(name, "LoadBalancerAttributes")
	p.key == "secondary_ips.auto_assigned.per_subnet"
	n := _pf_elb_num(p.value)
	_pf_elb_outside(n, 0, 7)
}
