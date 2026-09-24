package cdk_preflight

import rego.v1

# TargetOperations is a required list, and the schema is happy with an empty
# one. The hook handler is not, but it says so only as a generic
# GeneralServiceException, so nothing downstream names the property either.
_pf_cfnhookops_bad contains name if {
	some name in resources_of_type("AWS::CloudFormation::GuardHook")
	ops := resolve(name, "Properties.TargetOperations")
	is_array(ops)
	count(ops) == 0
}

violation contains make_diag_full("pf-cfn-hook-targetoperations-nonempty", "ERROR", name,
	"Properties.TargetOperations",
	"TargetOperations is empty; CloudFormation fails the hook with a bare \"Error occurred during operation 'AWS::CloudFormation::GuardHook'.\" (GeneralServiceException) that never names the property",
	"List at least one target operation, e.g. [\"RESOURCE\"]",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cloudformation-guardhook.html") if {
	some name in _pf_cfnhookops_bad
}
