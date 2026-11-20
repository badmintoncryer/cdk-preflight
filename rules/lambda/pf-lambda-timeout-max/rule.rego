package cdk_preflight

import rego.v1

# The cap was 900 until 2026-11-19, when Lambda raised it to 1800 for functions
# without CapacityProviderConfig (Lambda Managed Instances allow up to 5400,
# which the engine already enforces as F3034). Engines up to 1.17.1 still cap
# at 900 in E3717 (fixed upstream in cloudformation-validate #517), so this
# retired rule must not fire on 901..1800 where it still runs.
violation contains make_diag_full("pf-lambda-timeout-max", "ERROR", name,
	"Properties.Timeout",
	sprintf("Timeout %v is over the 30-minute cap for a function without CapacityProviderConfig; the function create fails", [t]),
	"Use at most 1800 seconds, or run the function on Lambda Managed Instances (CapacityProviderConfig)",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-lambda-function.html") if {
	some name in resources_of_type("AWS::Lambda::Function")
	not _pf_lto_has_cp(name)
	t := _pf_num(name, "Properties.Timeout")
	t > 1800
}

_pf_lto_has_cp(name) if resolve(name, "Properties.CapacityProviderConfig") != null
