package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-codebuild-vpc-subnets-max-16", "ERROR", name,
	"Properties.VpcConfig.Subnets",
	sprintf("%d subnets are named; CreateProject fails with \"Invalid vpc config: the maximum number of subnets is 16\"", [n]),
	"Keep VpcConfig.Subnets to 16 entries or fewer",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-codebuild-project-vpcconfig.html") if {
	some name in resources_of_type("AWS::CodeBuild::Project")
	_pf_countable_list(name, "Properties.VpcConfig.Subnets")
	n := count(flatten_list(name, "Properties.VpcConfig.Subnets"))
	n > 16
}
