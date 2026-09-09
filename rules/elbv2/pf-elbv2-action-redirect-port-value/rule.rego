package cdk_preflight

import rego.v1

_pf_elbarpv_fix := "Use a port between 1 and 65535, or the #{port} placeholder"

_pf_elbarpv_url := "https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_RedirectActionConfig.html"

_pf_elbarpv_ok(p) if {
	n := _pf_elb_num(p)
	not _pf_elb_outside(n, 1, 65535)
}

violation contains make_diag_full("pf-elbv2-action-redirect-port-value", "ERROR", name,
	sprintf("Properties.%s.%d.RedirectConfig.Port", [a.prop, a.index]),
	sprintf("The redirect port is '%v'; it has to be 1-65535 or the #{port} placeholder", [p]),
	_pf_elbarpv_fix, _pf_elbarpv_url) if {
	some a in _pf_elb_all_actions
	name := a.name
	rc := _pf_elb_oget(a.value, "RedirectConfig")
	p := _pf_elb_oget(rc, "Port")
	p != "#{port}"
	not _pf_elbarpv_ok(p)
}
