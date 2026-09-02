package cdk_preflight

import rego.v1

# The registry schema has the 128 floor but is missing the 10240 cap
# (engine clean on 20000, F3034 on 64).
violation contains make_diag_full("pf-lambda-memory-max", "ERROR", name,
	"Properties.MemorySize",
	sprintf("MemorySize %v is over the cap; the function create fails with \"'MemorySize' value failed to satisfy constraint: Member must have value less than or equal to 10240\"", [m]),
	"Use at most 10240 MB",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-lambda-function.html") if {
	some name in resources_of_type("AWS::Lambda::Function")
	m := to_number(resolve(name, "Properties.MemorySize"))
	m > 10240
}
