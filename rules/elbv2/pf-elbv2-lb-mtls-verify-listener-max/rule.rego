package cdk_preflight

import rego.v1

_pf_elblmvl_fix := "Keep two listeners in mutual authentication verify mode per load balancer (the quota cannot be raised)"

_pf_elblmvl_url := "https://docs.aws.amazon.com/elasticloadbalancing/latest/application/load-balancer-limits.html"

violation contains make_diag_full("pf-elbv2-lb-mtls-verify-listener-max", "ERROR", lb,
	"Properties",
	sprintf("The load balancer has %d listeners in mutual authentication 'verify' mode; the quota is 2", [n]),
	_pf_elblmvl_fix, _pf_elblmvl_url) if {
	some lb in _pf_elb_lbs
	n := count([l |
		some l in _pf_elb_listeners
		_pf_elb_lb_of(l) == lb
		ma := _pf_elb_oget(_pf_elb_props(l), "MutualAuthentication")
		is_object(ma)
		object.get(ma, "Mode", "off") == "verify"
	])
	n > 2
}
