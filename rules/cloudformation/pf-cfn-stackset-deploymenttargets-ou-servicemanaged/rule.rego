package cdk_preflight

import rego.v1

# A SELF_MANAGED stack set can only target accounts. Nothing in the schema
# ties DeploymentTargets to the permission model.
_pf_cfnssou_bad contains [name, idx] if {
	some name in resources_of_type("AWS::CloudFormation::StackSet")
	object.get(object.get(input.resources[name], "properties", {}), "PermissionModel", "SELF_MANAGED") == "SELF_MANAGED"
	some g in flatten_list(name, "Properties.StackInstancesGroup")
	ous := object.get(object.get(g.value, "DeploymentTargets", {}), "OrganizationalUnitIds", [])
	_pf_unconditional_items(ous)
	count(ous) > 0
	idx := g.index
}

violation contains make_diag_full("pf-cfn-stackset-deploymenttargets-ou-servicemanaged", "ERROR", name,
	sprintf("Properties.StackInstancesGroup.%d.DeploymentTargets.OrganizationalUnitIds", [idx]),
	"This SELF_MANAGED stack set targets organizational units; CloudFormation fails it with \"StackSets with SELF_MANAGED permission model can only have accounts as target\"",
	"Target accounts instead, or set PermissionModel: SERVICE_MANAGED",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cloudformation-stackset-deploymenttargets.html") if {
	some [name, idx] in _pf_cfnssou_bad
}
