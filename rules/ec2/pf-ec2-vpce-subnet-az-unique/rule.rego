package cdk_preflight

import rego.v1

# flatten_list の .value は生のマーカーオブジェクトなので、論理 ID はドット記法の
# resolve で取り直す（AGENTS.md: 配列要素は Properties.L.1）。AZ 側は解決できない
# 式のままでも構わない — 同じ式なら同じマーカーになり、等値比較が成立する。
_pf_ec2vaz_az(name, i) := az if {
	sref := resolve(name, sprintf("Properties.SubnetIds.%d", [i]))
	is_string(sref)
	az := resolve(sref, "Properties.AvailabilityZone")
}

_pf_ec2vaz_azs(name) := [az |
	some s in flatten_list(name, "Properties.SubnetIds")
	az := _pf_ec2vaz_az(name, s.index)
]

_pf_ec2vaz_dup(name) := az if {
	azs := _pf_ec2vaz_azs(name)
	some az in azs
	count([x | some x in azs; x == az]) > 1
}

violation contains make_diag_full("pf-ec2-vpce-subnet-az-unique", "ERROR", name,
	"Properties.SubnetIds",
	sprintf("SubnetIds names more than one subnet in '%s'; the create fails with \"Found another VPC endpoint subnet in the availability zone\"", [az]),
	"List one subnet per availability zone",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-ec2-vpcendpoint.html") if {
	some name in resources_of_type("AWS::EC2::VPCEndpoint")
	resolve(name, "Properties.VpcEndpointType") == "Interface"
	az := _pf_ec2vaz_dup(name)
}
