package cdk_preflight

import rego.v1

_pf_elbt6q_fix := "Drop IpAddressType ipv6, or use a TCP/UDP target group"

_pf_elbt6q_url := "https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_CreateTargetGroup.html"

violation contains make_diag_full("pf-elbv2-tg-ipv6-with-quic", "ERROR", name,
	"Properties.IpAddressType",
	sprintf("IpAddressType 'ipv6' with Protocol '%s'; QUIC target groups do not support IPv6", [p]),
	_pf_elbt6q_fix, _pf_elbt6q_url) if {
	some name in _pf_elb_tgs
	_pf_elb_str(name, "IpAddressType") == "ipv6"
	p := _pf_elb_str(name, "Protocol")
	p in {"QUIC", "TCP_QUIC"}
}
