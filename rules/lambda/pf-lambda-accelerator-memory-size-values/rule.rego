package cdk_preflight

import rego.v1

_pf_lams_ok := {3, 6, 12, 16, 24, 48}

violation contains make_diag_full("pf-lambda-accelerator-memory-size-values", "ERROR", name,
	"Properties.AcceleratorConfig.AcceleratorMemorySize",
	sprintf("AcceleratorMemorySize %v; valid values are 3, 6, 12, 16, 24 and 48", [n]),
	"Use 3, 6, 12, 16, 24 or 48 (GB)",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-lambda-function-acceleratorconfig.html") if {
	some name in resources_of_type("AWS::Lambda::Function")
	n := _pf_num(name, "Properties.AcceleratorConfig.AcceleratorMemorySize")
	not n in _pf_lams_ok
}
