package cdk_preflight

import rego.v1

# サブネットと VpcId は同じ VPC でなければならない（DirectoryVpcSettings）。
# 両方がテンプレート内の AWS::EC2::VPC を指すときだけ比べる。片方が取り込みの
# vpc-xxxx 文字列だと同じ VPC かどうか分からないので黙る。
_pf_dssv_vpc(ref) := v if {
	is_string(ref)
	ref in resources_of_type("AWS::EC2::VPC")
	v := ref
}

violation contains make_diag_full("pf-ds-msad-subnet-in-vpc", "ERROR", name,
	sprintf("Properties.VpcSettings.SubnetIds.%d", [s.index]),
	sprintf("Subnet %v belongs to VPC %v, but VpcSettings.VpcId is %v; the directory subnets must be in the directory's VPC", [sref, svpc, dvpc]),
	"Use subnets from the VPC named in VpcSettings.VpcId",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-directoryservice-microsoftad-vpcsettings.html") if {
	some name in resources_of_type("AWS::DirectoryService::MicrosoftAD")
	dvpc := _pf_dssv_vpc(resolve(name, "Properties.VpcSettings.VpcId"))
	some s in flatten_list(name, "Properties.VpcSettings.SubnetIds")
	sref := resolve(name, sprintf("Properties.VpcSettings.SubnetIds.%d", [s.index]))
	is_string(sref)
	sref in resources_of_type("AWS::EC2::Subnet")
	svpc := _pf_dssv_vpc(resolve(sref, "Properties.VpcId"))
	svpc != dvpc
}
