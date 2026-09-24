package cdk_preflight

import rego.v1

# Operation preferences are only validated when the stack set actually has
# instances to operate on: the same template without StackInstancesGroup
# deploys clean (measured 2026-09-25), so the empty case is not a violation.
_pf_cfnssft_bad contains name if {
	some name in resources_of_type("AWS::CloudFormation::StackSet")
	count(flatten_list(name, "Properties.StackInstancesGroup")) > 0
	op := object.get(object.get(input.resources[name], "properties", {}), "OperationPreferences", {})
	object.get(op, "FailureToleranceCount", null) != null
	object.get(op, "FailureTolerancePercentage", null) != null
}

violation contains make_diag_full("pf-cfn-stackset-failuretolerance-exclusive", "ERROR", name,
	"Properties.OperationPreferences",
	"OperationPreferences sets both FailureToleranceCount and FailureTolerancePercentage; with stack instances to deploy, CloudFormation fails the stack set with \"Exactly one of FailureToleranceCount or FailureTolerancePercentage must be specified\"",
	"Keep one of the two and delete the other",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cloudformation-stackset-operationpreferences.html") if {
	some name in _pf_cfnssft_bad
}
