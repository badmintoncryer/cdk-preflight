package cdk_preflight

import rego.v1

_pf_elbarhh_fix := "Redirect to HTTPS, or leave Protocol as #{protocol}"

_pf_elbarhh_url := "https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_RedirectActionConfig.html"

violation contains make_diag_full("pf-elbv2-action-redirect-https-to-http", "ERROR", name,
	sprintf("Properties.%s.%d.RedirectConfig.Protocol", [a.prop, a.index]),
	"The redirect sends an HTTPS listener back to HTTP; the service only allows HTTP to HTTPS, not the other way around",
	_pf_elbarhh_fix, _pf_elbarhh_url) if {
	some a in _pf_elb_all_actions
	name := a.name
	rc := _pf_elb_oget(a.value, "RedirectConfig")
	object.get(rc, "Protocol", "#{protocol}") == "HTTP"
	_pf_elb_listener_proto(name) == "HTTPS"
}
