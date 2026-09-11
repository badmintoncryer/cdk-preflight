package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-batch-jd-linux-swappiness-range", "ERROR", name,
	"Properties.ContainerProperties.LinuxParameters.Swappiness",
	sprintf("Swappiness is %v (\"Invalid swappiness: %v, must be between 0 and 100.\")", [n, n]),
	"Use a swappiness between 0 and 100",
	"https://docs.aws.amazon.com/batch/latest/APIReference/API_LinuxParameters.html") if {
	some name in resources_of_type("AWS::Batch::JobDefinition")
	n := to_number(resolve(name, "Properties.ContainerProperties.LinuxParameters.Swappiness"))
	_pf_batch_outside(n, 0, 100)
}
