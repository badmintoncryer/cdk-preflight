package cdk_preflight

import rego.v1

# Two independent enums the schema never cross-checks.
_pf_cfnsscallas_bad contains name if {
	some name in resources_of_type("AWS::CloudFormation::StackSet")
	props := object.get(input.resources[name], "properties", {})
	object.get(props, "CallAs", "SELF") == "DELEGATED_ADMIN"
	object.get(props, "PermissionModel", "SELF_MANAGED") != "SERVICE_MANAGED"
}

violation contains make_diag_full("pf-cfn-stackset-callas-delegated-servicemanaged-only", "ERROR", name,
	"Properties.CallAs",
	"CallAs is DELEGATED_ADMIN but the stack set is not SERVICE_MANAGED; CloudFormation fails it with \"You can only operate on SERVICE_MANAGED StackSets as a delegated administrator\"",
	"Use CallAs: SELF, or set PermissionModel: SERVICE_MANAGED",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cloudformation-stackset.html") if {
	some name in _pf_cfnsscallas_bad
}
