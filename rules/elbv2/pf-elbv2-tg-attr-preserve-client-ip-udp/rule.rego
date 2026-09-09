package cdk_preflight

import rego.v1

_pf_elbgpci_fix := "Leave preserve_client_ip.enabled at true on a UDP, TCP_UDP or QUIC target group"

_pf_elbgpci_url := "https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_TargetGroupAttribute.html"

violation contains make_diag_full("pf-elbv2-tg-attr-preserve-client-ip-udp", "ERROR", name,
	sprintf("Properties.TargetGroupAttributes.%d.Value", [p.index]),
	sprintf("preserve_client_ip.enabled is 'false' on a %s target group; client IP preservation cannot be disabled for UDP-based target groups", [proto]),
	_pf_elbgpci_fix, _pf_elbgpci_url) if {
	some name in _pf_elb_tgs
	some p in _pf_elb_pairs(name, "TargetGroupAttributes")
	p.key == "preserve_client_ip.enabled"
	p.value == "false"
	proto := _pf_elb_str(name, "Protocol")
	proto in {"UDP", "TCP_UDP", "QUIC", "TCP_QUIC"}
}
