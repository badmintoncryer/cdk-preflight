package cdk_preflight

import rego.v1

_pf_elblsvm_fix := "Create the security group in the VPC the subnets belong to"

_pf_elblsvm_url := "https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_CreateLoadBalancer.html"

violation contains make_diag_full("pf-elbv2-lb-sg-vpc-match", "ERROR", lb,
	sprintf("Properties.SecurityGroups.%d", [g.index]),
	sprintf("Security group '%s' is in VPC '%s' but the subnets are in VPC '%s'", [sg, sgvpc, vpc]),
	_pf_elblsvm_fix, _pf_elblsvm_url) if {
	some lb in _pf_elb_lbs
	vpc := _pf_elb_lb_vpc(lb)
	some g in flatten_list(lb, "Properties.SecurityGroups")
	sg := _pf_elb_ref(g.value)
	sgvpc := resolve(sg, "Properties.VpcId")
	sgvpc != vpc
}
