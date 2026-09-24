package cdk_preflight

import rego.v1

# Same gate as the failure-tolerance pair: only checked once the stack set has
# instances to operate on.
_pf_cfnssmc_bad contains name if {
	some name in resources_of_type("AWS::CloudFormation::StackSet")
	_pf_unconditional_list(name, "Properties.StackInstancesGroup")
	count(flatten_list(name, "Properties.StackInstancesGroup")) > 0
	op := object.get(object.get(input.resources[name], "properties", {}), "OperationPreferences", {})
	object.get(op, "MaxConcurrentCount", null) != null
	object.get(op, "MaxConcurrentPercentage", null) != null
}

violation contains make_diag_full("pf-cfn-stackset-maxconcurrent-exclusive", "ERROR", name,
	"Properties.OperationPreferences",
	"OperationPreferences sets both MaxConcurrentCount and MaxConcurrentPercentage; with stack instances to deploy, CloudFormation fails the stack set with \"Exactly one of MaxConcurrentCount or MaxConcurrentPercentage must be specified\"",
	"Keep one of the two and delete the other",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cloudformation-stackset-operationpreferences.html") if {
	some name in _pf_cfnssmc_bad
}
