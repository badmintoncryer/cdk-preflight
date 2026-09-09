package cdk_preflight

import rego.v1

_pf_elbtgp_fix := "Set Port to 6081"

_pf_elbtgp_url := "https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_CreateTargetGroup.html"

violation contains make_diag_full("pf-elbv2-tg-geneve-port", "ERROR", name,
	"Properties.Port",
	sprintf("A GENEVE target group is on port %v; the protocol only runs on 6081", [port]),
	_pf_elbtgp_fix, _pf_elbtgp_url) if {
	some name in _pf_elb_tgs
	_pf_elb_str(name, "Protocol") == "GENEVE"
	port := resolve(name, "Properties.Port")
	is_number(port)
	port != 6081
}
