package cdk_preflight

import rego.v1

_pf_lvne_fix := "Give VpcConfig both SubnetIds and SecurityGroupIds, or drop VpcConfig entirely"

_pf_lvne_url := "https://docs.aws.amazon.com/lambda/latest/dg/foundation-networking.html"

violation contains make_diag_full("pf-lambda-vpc-non-empty", "ERROR", name,
	sprintf("Properties.VpcConfig.%v", [key]),
	sprintf("VpcConfig with an empty %v; a VPC function needs at least one subnet and one security group, and an empty list is rejected", [key]),
	_pf_lvne_fix, _pf_lvne_url) if {
	some name in _pf_lam_fn
	cfg := _pf_lam_vpccfg(name)
	some key in ["SubnetIds", "SecurityGroupIds"]
	l := object.get(cfg, key, "__pf_absent")
	is_array(l)
	count(l) == 0
}
