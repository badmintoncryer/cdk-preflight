package cdk_preflight

import rego.v1

_pf_lvdt_fix := "Attach the function to a VPC with default instance tenancy"

_pf_lvdt_url := "https://docs.aws.amazon.com/lambda/latest/dg/foundation-networking.html"

violation contains make_diag_full("pf-lambda-vpc-no-dedicated-tenancy", "ERROR", name,
	"Properties.VpcConfig.SubnetIds",
	"a subnet in a dedicated-tenancy VPC; Lambda runs its ENIs on shared hardware and rejects dedicated tenancy",
	_pf_lvdt_fix, _pf_lvdt_url) if {
	some name in _pf_lam_fn
	cfg := _pf_lam_vpccfg(name)
	some sub in _pf_lam_list(object.get(cfg, "SubnetIds", []))
	vpc := _pf_lam_vpc_of(sub)
	object.get(_pf_lam_res_props(_pf_lam_ref(vpc)), "InstanceTenancy", "default") == "dedicated"
}
