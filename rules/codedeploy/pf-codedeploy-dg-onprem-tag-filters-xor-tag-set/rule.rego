package cdk_preflight

import rego.v1

# Same exclusivity as the EC2 pair, enforced by its own exception.
violation contains make_diag_full("pf-codedeploy-dg-onprem-tag-filters-xor-tag-set", "ERROR", name,
	"Properties.OnPremisesTagSet",
	"OnPremisesInstanceTagFilters and OnPremisesTagSet are both set; the deployment group create fails with \"The request specified both OnPremisesTagFilters and OnPremisesTagSet, but only one of these data types can be used in a single call.\"",
	"Keep one: OnPremisesInstanceTagFilters for a flat OR of tags, OnPremisesTagSet for groups that must all match",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-codedeploy-deploymentgroup.html") if {
	some name in resources_of_type("AWS::CodeDeploy::DeploymentGroup")
	p := _pf_codedeploylib_props(name)
	_pf_codedeploylib_has(p, "OnPremisesInstanceTagFilters")
	_pf_codedeploylib_has(p, "OnPremisesTagSet")
}
