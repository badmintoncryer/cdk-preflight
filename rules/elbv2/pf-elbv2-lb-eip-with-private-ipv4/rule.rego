package cdk_preflight

import rego.v1

_pf_elbeipp_fix := "Keep either AllocationId (internet-facing) or PrivateIPv4Address (internal) in a mapping"

_pf_elbeipp_url := "https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_CreateLoadBalancer.html"

violation contains make_diag_full("pf-elbv2-lb-eip-with-private-ipv4", "ERROR", name,
	sprintf("Properties.SubnetMappings.%d", [m.index]),
	"The subnet mapping carries both AllocationId and PrivateIPv4Address; the two address forms are mutually exclusive in one mapping",
	_pf_elbeipp_fix, _pf_elbeipp_url) if {
	some name in _pf_elb_lbs
	some m in flatten_list(name, "Properties.SubnetMappings")
	_pf_elb_ohas(m.value, "AllocationId")
	_pf_elb_ohas(m.value, "PrivateIPv4Address")
}
