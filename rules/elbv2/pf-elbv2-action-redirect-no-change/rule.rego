package cdk_preflight

import rego.v1

_pf_elbarnc_fix := "Change the protocol, host, port or path (a query-only redirect still loops)"

_pf_elbarnc_url := "https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_RedirectActionConfig.html"

_pf_elbarnc_keep := {
	"Protocol": "#{protocol}",
	"Host": "#{host}",
	"Port": "#{port}",
	"Path": "/#{path}",
}

violation contains make_diag_full("pf-elbv2-action-redirect-no-change", "ERROR", name,
	sprintf("Properties.%s.%d.RedirectConfig", [a.prop, a.index]),
	"The redirect keeps the protocol, host, port and path of the request, so it would answer every request with a redirect to itself",
	_pf_elbarnc_fix, _pf_elbarnc_url) if {
	some a in _pf_elb_all_actions
	name := a.name
	rc := _pf_elb_oget(a.value, "RedirectConfig")
	changed := {k |
		some k, ph in _pf_elbarnc_keep
		object.get(rc, k, ph) != ph
	}
	count(changed) == 0
}
