package cdk_preflight

import rego.v1

# The green fleet is a copy of the blue one, so there has to be exactly one blue
# Auto Scaling group to copy. Zero groups and two groups are refused with the
# same message.
_pf_cdcasg_one(name) if {
	a := object.get(_pf_codedeploylib_props(name), "AutoScalingGroups", null)
	is_array(a)
	_pf_countable_items(a)
	count(a) == 1
}

_pf_cdcasg_one(name) if {
	a := object.get(_pf_codedeploylib_props(name), "AutoScalingGroups", null)
	a != null
	not is_array(a)
}

violation contains make_diag_full("pf-codedeploy-dg-copy-asg-requires-asg", "ERROR", name,
	"Properties.AutoScalingGroups",
	"GreenFleetProvisioningOption.Action is COPY_AUTO_SCALING_GROUP but AutoScalingGroups does not name exactly one group; the deployment group create fails with \"Exactly one AutoScaling group must be specified when selecting the COPY_AUTO_SCALING_GROUP green fleet provisioning option.\"",
	"Name exactly one Auto Scaling group in AutoScalingGroups, or use GreenFleetProvisioningOption DISCOVER_EXISTING",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-codedeploy-deploymentgroup-greenfleetprovisioningoption.html") if {
	some name in resources_of_type("AWS::CodeDeploy::DeploymentGroup")
	bg := _pf_codedeploylib_obj(_pf_codedeploylib_props(name), "BlueGreenDeploymentConfiguration")
	gf := _pf_codedeploylib_obj(bg, "GreenFleetProvisioningOption")
	object.get(gf, "Action", null) == "COPY_AUTO_SCALING_GROUP"
	not _pf_cdcasg_one(name)
}
