package cdk_preflight

import rego.v1

# クロスリソース: SubnetIds の各要素が同じテンプレートの AWS::EC2::Subnet なら、その VpcId
# はエンドポイントの VpcId と同じでなければならない。Ref はどちらも論理 ID に解決される
# ので文字列で比べられる。import した subnet ID は解決できないので対象外。
violation contains make_diag_full("pf-neptunegraph-private-endpoint-subnet-vpc-match", "ERROR", name,
	sprintf("Properties.SubnetIds.%d", [s.index]),
	sprintf("Subnet %s belongs to VPC %s but the endpoint's VpcId is %s; Neptune Analytics rejects the endpoint at create time", [sref, sv, vpc]),
	"List only subnets of the VPC named in VpcId",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-neptunegraph-privategraphendpoint.html") if {
	some name in resources_of_type("AWS::NeptuneGraph::PrivateGraphEndpoint")
	vpc := resolve(name, "Properties.VpcId")
	is_string(vpc)
	some s in flatten_list(name, "Properties.SubnetIds")
	sref := resolve(name, sprintf("Properties.SubnetIds.%d", [s.index]))
	is_string(sref)
	input.resources[sref].resourceType == "AWS::EC2::Subnet"
	sv := resolve(sref, "Properties.VpcId")
	is_string(sv)
	sv != vpc
}
