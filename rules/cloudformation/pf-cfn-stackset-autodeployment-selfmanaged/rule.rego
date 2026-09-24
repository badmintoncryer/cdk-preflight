package cdk_preflight

import rego.v1

# AutoDeployment belongs to the SERVICE_MANAGED permission model only; the
# schema lets it sit next to either one. PermissionModel defaults to
# SELF_MANAGED when it is absent, which is exactly the case that surprises.
_pf_cfnssad_bad contains name if {
	some name in resources_of_type("AWS::CloudFormation::StackSet")
	props := object.get(input.resources[name], "properties", {})
	object.get(props, "PermissionModel", "SELF_MANAGED") == "SELF_MANAGED"
	is_object(object.get(props, "AutoDeployment", null))
}

violation contains make_diag_full("pf-cfn-stackset-autodeployment-selfmanaged", "ERROR", name,
	"Properties.AutoDeployment",
	"AutoDeployment is set on a SELF_MANAGED stack set (PermissionModel defaults to SELF_MANAGED); CloudFormation fails the stack set with \"AutoDeployment is not supported\"",
	"Drop AutoDeployment, or switch the stack set to PermissionModel: SERVICE_MANAGED",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cloudformation-stackset.html") if {
	some name in _pf_cfnssad_bad
}
