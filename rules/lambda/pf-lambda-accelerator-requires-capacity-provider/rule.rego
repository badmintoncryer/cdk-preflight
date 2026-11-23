package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-lambda-accelerator-requires-capacity-provider", "ERROR", name,
	"Properties.AcceleratorConfig",
	"AcceleratorConfig without CapacityProviderConfig; accelerators run only on Lambda Managed Instances",
	"Add CapacityProviderConfig with a GPU capacity provider, or drop AcceleratorConfig",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-lambda-function-acceleratorconfig.html") if {
	some name in resources_of_type("AWS::Lambda::Function")
	resolve(name, "Properties.AcceleratorConfig") != null
	not _pf_lacp_has_cp(name)
}

_pf_lacp_has_cp(name) if resolve(name, "Properties.CapacityProviderConfig") != null
