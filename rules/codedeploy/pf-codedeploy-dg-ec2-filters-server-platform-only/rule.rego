package cdk_preflight

import rego.v1

# Tag filters pick EC2 or on-premises instances to deploy to, which the Lambda
# and ECS platforms do not have. All four targeting properties are refused, each
# with its own exception but the same sentence.
violation contains make_diag_full("pf-codedeploy-dg-ec2-filters-server-platform-only", "ERROR", name,
	sprintf("Properties.%v", [k]),
	sprintf("%v is set on a deployment group whose application is the %v compute platform; the create fails with \"For %v deployment group, %v%v can not be specified\"", [k, p, upper(p), lower(substring(k, 0, 1)), substring(k, 1, -1)]),
	sprintf("Drop %v - only the Server (EC2/on-premises) platform selects instances by tag", [k]),
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-codedeploy-deploymentgroup.html") if {
	some name in resources_of_type("AWS::CodeDeploy::DeploymentGroup")
	p := _pf_codedeploylib_dg_platform(name)
	p != "Server"
	some k in ["Ec2TagFilters", "Ec2TagSet", "OnPremisesInstanceTagFilters", "OnPremisesTagSet"]
	_pf_codedeploylib_has(_pf_codedeploylib_props(name), k)
}
