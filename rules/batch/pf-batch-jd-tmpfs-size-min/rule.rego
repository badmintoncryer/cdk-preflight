package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-batch-jd-tmpfs-size-min", "ERROR", name,
	"Properties.ContainerProperties.LinuxParameters.Tmpfs",
	sprintf("a tmpfs mount asks for %v MiB (\"Size of a tmpfs is invalid. The size is required and must be a positive integer.\")", [n]),
	"Request at least 1 MiB",
	"https://docs.aws.amazon.com/batch/latest/APIReference/API_Tmpfs.html") if {
	some name in resources_of_type("AWS::Batch::JobDefinition")
	some t in flatten_list(name, "Properties.ContainerProperties.LinuxParameters.Tmpfs")
	n := to_number(_pf_batch_oget(t.value, "Size"))
	n < 1
}
