package cdk_preflight

import rego.v1

_pf_elblmh_fix := "Drop MutualAuthentication unless the listener protocol is HTTPS"

_pf_elblmh_url := "https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_MutualAuthenticationAttributes.html"

violation contains make_diag_full("pf-elbv2-listener-mtls-https-only", "ERROR", name,
	"Properties.MutualAuthentication",
	sprintf("MutualAuthentication is set on a %s listener; mutual TLS is only configured on an HTTPS listener of an Application Load Balancer", [proto]),
	_pf_elblmh_fix, _pf_elblmh_url) if {	some name in _pf_elb_listeners
	ma := resolve(name, "Properties.MutualAuthentication")
	is_object(ma)
	proto := object.get(_pf_elb_props(name), "Protocol", "GENEVE")
	proto != "HTTPS"
}
