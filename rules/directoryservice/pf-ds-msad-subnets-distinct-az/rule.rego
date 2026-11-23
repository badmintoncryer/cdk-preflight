package cdk_preflight

import rego.v1

# DirectoryVpcSettings: "The two subnets must be in different Availability Zones."
# AZ は解決できない式（Fn::Select/GetAZs）のままでも、同じ式なら等値比較が成立する
# （pf-ec2-vpce-subnet-az-unique と同じ考え方）。サブネットが取り込みの ID なら黙る。
_pf_dsaz_az(name, i) := az if {
	sref := resolve(name, sprintf("Properties.VpcSettings.SubnetIds.%d", [i]))
	is_string(sref)
	sref in resources_of_type("AWS::EC2::Subnet")
	az := resolve(sref, "Properties.AvailabilityZone")
}

_pf_dsaz_dup(name) := az if {
	_pf_static_list(name, "Properties.VpcSettings.SubnetIds")
	azs := [a | some s in flatten_list(name, "Properties.VpcSettings.SubnetIds"); a := _pf_dsaz_az(name, s.index)]
	some az in azs
	count([x | some x in azs; x == az]) > 1
}

violation contains make_diag_full("pf-ds-msad-subnets-distinct-az", "ERROR", name,
	"Properties.VpcSettings.SubnetIds",
	"VpcSettings.SubnetIds puts both directory subnets in the same Availability Zone; AWS Managed Microsoft AD needs them in different Availability Zones",
	"Choose two subnets in different Availability Zones",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-directoryservice-microsoftad-vpcsettings.html") if {
	some name in resources_of_type("AWS::DirectoryService::MicrosoftAD")
	_pf_dsaz_dup(name)
}
