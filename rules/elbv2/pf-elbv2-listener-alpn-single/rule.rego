package cdk_preflight

import rego.v1

_pf_elblas_fix := "Keep one ALPN policy"

_pf_elblas_url := "https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_CreateListener.html"

violation contains make_diag_full("pf-elbv2-listener-alpn-single", "ERROR", name,
	"Properties.AlpnPolicy",
	sprintf("%d ALPN policies are set; a listener negotiates with exactly one", [n]),
	_pf_elblas_fix, _pf_elblas_url) if {
	some name in _pf_elb_listeners
	n := count(flatten_list(name, "Properties.AlpnPolicy"))
	n > 1
}
