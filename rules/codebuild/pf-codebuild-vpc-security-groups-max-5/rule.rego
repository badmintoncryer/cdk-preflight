package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-codebuild-vpc-security-groups-max-5", "ERROR", name,
	"Properties.VpcConfig.SecurityGroupIds",
	sprintf("%d security groups are named; CreateProject fails with \"Invalid vpc config: the maximum number of security groups is 5\"", [n]),
	"Keep VpcConfig.SecurityGroupIds to 5 entries or fewer",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-codebuild-project-vpcconfig.html") if {
	some name in resources_of_type("AWS::CodeBuild::Project")
	n := count(flatten_list(name, "Properties.VpcConfig.SecurityGroupIds"))
	n > 5
}
