package cdk_preflight

import rego.v1

_pf_elblsk_fix := "Use a predefined ELBSecurityPolicy-* name (there are no custom policies)"

_pf_elblsk_url := "https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_CreateListener.html"

violation contains make_diag_full("pf-elbv2-listener-sslpolicy-known", "ERROR", name,
	"Properties.SslPolicy",
	sprintf("'%s' is not a predefined security policy; CreateListener only accepts the ELBSecurityPolicy-* names the service publishes", [pol]),
	_pf_elblsk_fix, _pf_elblsk_url) if {
	some name in _pf_elb_listeners
	pol := _pf_elb_str(name, "SslPolicy")
	not pol in _pf_elb_sslpolicies
}
