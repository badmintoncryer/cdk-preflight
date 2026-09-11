package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-batch-jd-fargate-ephemeral-storage-range", "ERROR", name,
	"Properties.ContainerProperties.EphemeralStorage.SizeInGiB",
	sprintf("EphemeralStorage.SizeInGiB is %v (\"Ephemeral storage for Fargate tasks can be only between range 21 GiB to 200 GiB\")", [n]),
	"Use a size between 21 and 200 GiB",
	"https://docs.aws.amazon.com/batch/latest/APIReference/API_EphemeralStorage.html") if {
	some name in resources_of_type("AWS::Batch::JobDefinition")
	_pf_batch_fargate(name)
	n := to_number(resolve(name, "Properties.ContainerProperties.EphemeralStorage.SizeInGiB"))
	_pf_batch_outside(n, 21, 200)
}
