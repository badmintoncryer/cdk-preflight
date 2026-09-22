package cdk_preflight

import rego.v1

# 全 SubnetIds が同じテンプレートの AWS::EC2::Subnet で AZ がリテラルのときだけ判定する。
# Fn::GetAZs / Fn::Select で AZ を選ぶ CDK の Vpc や import した subnet ID は解決できないので
# 対象外（under-claim）。配列要素は Properties.SubnetIds.<i> で解決する（AGENTS.md）。
_pf_nepsg_az(name, i) := az if {
	sref := resolve(name, sprintf("Properties.SubnetIds.%d", [i]))
	is_string(sref)
	input.resources[sref].resourceType == "AWS::EC2::Subnet"
	az := resolve(sref, "Properties.AvailabilityZone")
	is_string(az)
}

_pf_nepsg_azs(name) := [az |
	some s in flatten_list(name, "Properties.SubnetIds")
	az := _pf_nepsg_az(name, s.index)
]

_pf_nepsg_multi(name) if {
	azs := _pf_nepsg_azs(name)
	some az in azs
	count([x | some x in azs; x != az]) > 0
}

violation contains make_diag_full("pf-neptune-subnet-group-two-az", "ERROR", name,
	"Properties.SubnetIds",
	sprintf("SubnetIds covers only Availability Zone %s; Neptune requires at least two (\"The DB subnet group doesn't meet Availability Zone (AZ) coverage requirement. Current AZ coverage: us-east-1a. Add subnets to cover at least 2 AZs.\")", [azs[0]]),
	"Add a subnet in a second Availability Zone",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-neptune-dbsubnetgroup.html") if {
	some name in resources_of_type("AWS::Neptune::DBSubnetGroup")
	ids := flatten_list(name, "Properties.SubnetIds")
	count(ids) > 0
	azs := _pf_nepsg_azs(name)
	count(azs) == count(ids)
	not _pf_nepsg_multi(name)
}
