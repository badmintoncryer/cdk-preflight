package cdk_preflight

import rego.v1

# Fargate has its own tier table (pf-batch-fargate-cpu-memory); only the
# EC2 side carries the "at least 1" floor.
violation contains make_diag_full("pf-batch-jd-resource-requirements-vcpu-min", "ERROR", name,
	"Properties.ContainerProperties.ResourceRequirements",
	sprintf("VCPU is %v (\"vCPU must be at least 1, got %v.\")", [n, n]),
	"Request at least 1 vCPU, or run the job on Fargate",
	"https://docs.aws.amazon.com/batch/latest/APIReference/API_ResourceRequirement.html") if {
	some name in resources_of_type("AWS::Batch::JobDefinition")
	not _pf_batch_fargate(name)
	v := _pf_batch_rr(_pf_batch_cp(name), "VCPU")
	_pf_batch_lit(v)
	n := to_number(v)
	n < 1
}
