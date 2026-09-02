package cdk_preflight

import rego.v1

# The registry schema has the 1 floor but is missing the 900 cap (engine
# clean on 901, F3034 on 0).
violation contains make_diag_full("pf-lambda-timeout-max", "ERROR", name,
	"Properties.Timeout",
	sprintf("Timeout %v is over the 15-minute cap; the function create fails with \"Value '%v' at 'timeout' failed to satisfy constraint: Member must have value less than or equal to 900\"", [t, t]),
	"Use at most 900 seconds",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-lambda-function.html") if {
	some name in resources_of_type("AWS::Lambda::Function")
	t := to_number(resolve(name, "Properties.Timeout"))
	t > 900
}
