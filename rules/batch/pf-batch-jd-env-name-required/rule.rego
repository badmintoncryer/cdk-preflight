package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-batch-jd-env-name-required", "ERROR", name,
	"Properties.ContainerProperties.Environment",
	"an Environment entry has no Name (\"Environment variable name is required.\")",
	"Give the environment variable a Name",
	"https://docs.aws.amazon.com/batch/latest/APIReference/API_ContainerProperties.html") if {
	some name in resources_of_type("AWS::Batch::JobDefinition")
	some e in flatten_list(name, "Properties.ContainerProperties.Environment")
	is_object(e.value)
	not _pf_batch_ohas(e.value, "Name")
}
