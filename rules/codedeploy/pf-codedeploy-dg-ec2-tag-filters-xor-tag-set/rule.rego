package cdk_preflight

import rego.v1

# The two express the same selection differently (a flat OR-list versus groups
# ANDed together), and the service will not merge them.
violation contains make_diag_full("pf-codedeploy-dg-ec2-tag-filters-xor-tag-set", "ERROR", name,
	"Properties.Ec2TagSet",
	"Ec2TagFilters and Ec2TagSet are both set; the deployment group create fails with \"The request specified both Ec2TagFilters and Ec2TagSet, but only one of these data types can be used in a single call.\"",
	"Keep one: Ec2TagFilters for a flat OR of tags, Ec2TagSet for groups that must all match",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-codedeploy-deploymentgroup.html") if {
	some name in resources_of_type("AWS::CodeDeploy::DeploymentGroup")
	p := _pf_codedeploylib_props(name)
	_pf_codedeploylib_has(p, "Ec2TagFilters")
	_pf_codedeploylib_has(p, "Ec2TagSet")
}
