package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-batch-jd-linux-max-swap-negative", "ERROR", name,
	"Properties.ContainerProperties.LinuxParameters.MaxSwap",
	sprintf("MaxSwap is %v (\"Invalid swap memory size: %v, must be non-negative.\")", [n, n]),
	"Use 0 (swap disabled) or a positive limit",
	"https://docs.aws.amazon.com/batch/latest/APIReference/API_LinuxParameters.html") if {
	some name in resources_of_type("AWS::Batch::JobDefinition")
	n := to_number(resolve(name, "Properties.ContainerProperties.LinuxParameters.MaxSwap"))
	n < 0
}
