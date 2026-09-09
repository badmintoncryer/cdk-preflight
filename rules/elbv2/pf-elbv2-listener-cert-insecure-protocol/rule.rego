package cdk_preflight

import rego.v1

_pf_elblci_fix := "Drop Certificates, or make the listener HTTPS (ALB) or TLS (NLB)"

_pf_elblci_url := "https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_CreateListener.html"

violation contains make_diag_full("pf-elbv2-listener-cert-insecure-protocol", "ERROR", name,
	"Properties.Certificates",
	sprintf("A certificate is attached to a %s listener; only HTTPS and TLS listeners terminate TLS", [proto]),
	_pf_elblci_fix, _pf_elblci_url) if {
	some name in _pf_elb_listeners
	count(flatten_list(name, "Properties.Certificates")) > 0
	proto := object.get(_pf_elb_props(name), "Protocol", "GENEVE")
	not proto in _pf_elb_secure
}
