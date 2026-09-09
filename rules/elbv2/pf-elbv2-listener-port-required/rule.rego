package cdk_preflight

import rego.v1

_pf_elblpr_fix := "Set Port on the listener"

_pf_elblpr_url := "https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_CreateListener.html"

violation contains make_diag_full("pf-elbv2-listener-port-required", "ERROR", name,
	"Properties.Port",
	sprintf("The listener on a %s load balancer has no Port; only a gateway load balancer listener may omit it", [t]),
	_pf_elblpr_fix, _pf_elblpr_url) if {
	some name in _pf_elb_listeners
	t := _pf_elb_listener_lbtype(name)
	t != "gateway"
	_pf_elb_absent(name, "Port")
}
