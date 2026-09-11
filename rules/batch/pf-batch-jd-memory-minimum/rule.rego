package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-batch-jd-memory-minimum", "ERROR", name,
	"Properties.ContainerProperties.Memory",
	sprintf("Memory is %v MiB (\"Memory must be at least 4 Mib, got %v Mib.\")", [m, m]),
	"Request at least 4 MiB",
	"https://docs.aws.amazon.com/batch/latest/APIReference/API_ContainerProperties.html") if {
	some name in resources_of_type("AWS::Batch::JobDefinition")
	m := to_number(resolve(name, "Properties.ContainerProperties.Memory"))
	m < 4
}
