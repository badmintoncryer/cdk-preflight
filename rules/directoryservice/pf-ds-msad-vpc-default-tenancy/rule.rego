package cdk_preflight

import rego.v1

# Getting started: "The VPC must have default hardware tenancy."
violation contains make_diag_full("pf-ds-msad-vpc-default-tenancy", "ERROR", name,
	"Properties.VpcSettings.VpcId",
	sprintf("VPC %v has InstanceTenancy 'dedicated'; AWS Managed Microsoft AD needs a VPC with default hardware tenancy", [vpc]),
	"Create the directory in a VPC whose InstanceTenancy is 'default'",
	"https://docs.aws.amazon.com/directoryservice/latest/admin-guide/ms_ad_getting_started.html") if {
	some name in resources_of_type("AWS::DirectoryService::MicrosoftAD")
	vpc := resolve(name, "Properties.VpcSettings.VpcId")
	is_string(vpc)
	vpc in resources_of_type("AWS::EC2::VPC")
	resolve(vpc, "Properties.InstanceTenancy") == "dedicated"
}
