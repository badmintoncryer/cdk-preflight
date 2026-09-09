package cdk_preflight

import rego.v1

_pf_elbt6l_fix := "Drop IpAddressType on a lambda target group"

_pf_elbt6l_url := "https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_CreateTargetGroup.html"

violation contains make_diag_full("pf-elbv2-tg-ipv6-with-lambda", "ERROR", name,
	"Properties.IpAddressType",
	"IpAddressType 'ipv6' is set on a lambda target group; a Lambda target is not addressed by IP",
	_pf_elbt6l_fix, _pf_elbt6l_url) if {
	some name in _pf_elb_tgs
	_pf_elb_tgtype(name) == "lambda"
	_pf_elb_str(name, "IpAddressType") == "ipv6"
}
