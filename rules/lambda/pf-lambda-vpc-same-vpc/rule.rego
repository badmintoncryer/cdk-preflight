package cdk_preflight

import rego.v1

_pf_lvsv_fix := "Pick subnets and security groups from the same VPC"

_pf_lvsv_url := "https://docs.aws.amazon.com/lambda/latest/dg/foundation-networking.html"

violation contains make_diag_full("pf-lambda-vpc-same-vpc", "ERROR", name,
	"Properties.VpcConfig",
	"subnets and security groups from different VPCs; the create fails with \"Security group ... and subnet ... belong to different networks\"",
	_pf_lvsv_fix, _pf_lvsv_url) if {
	some name in _pf_lam_fn
	cfg := _pf_lam_vpccfg(name)
	some sub in _pf_lam_list(object.get(cfg, "SubnetIds", []))
	some sg in _pf_lam_list(object.get(cfg, "SecurityGroupIds", []))
	_pf_lam_vpc_of(sub) != _pf_lam_vpc_of(sg)
}
