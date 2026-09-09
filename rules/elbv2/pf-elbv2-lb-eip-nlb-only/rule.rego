package cdk_preflight

import rego.v1

_pf_elbeip_fix := "Drop SubnetMappings[].AllocationId, or make this a network load balancer"

_pf_elbeip_url := "https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_CreateLoadBalancer.html"

violation contains make_diag_full("pf-elbv2-lb-eip-nlb-only", "ERROR", name,
	sprintf("Properties.SubnetMappings.%d.AllocationId", [m.index]),
	sprintf("An Elastic IP is mapped on a %s load balancer; CreateLoadBalancer fails with \"Elastic IPs are not supported for load balancers with type '%s'\"", [t, t]),
	_pf_elbeip_fix, _pf_elbeip_url) if {
	some name in _pf_elb_lbs
	t := _pf_elb_lbtype(name)
	t != "network"
	some m in flatten_list(name, "Properties.SubnetMappings")
	_pf_elb_ohas(m.value, "AllocationId")
}
