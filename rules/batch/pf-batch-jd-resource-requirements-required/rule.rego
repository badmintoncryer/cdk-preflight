package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-batch-jd-resource-requirements-required", "ERROR", name,
	"Properties.ContainerProperties.ResourceRequirements",
	"neither a VCPU resource requirement nor the legacy Vcpus field is set (\"vCPU is required.\")",
	"Add a ResourceRequirements entry of type VCPU",
	"https://docs.aws.amazon.com/batch/latest/APIReference/API_ResourceRequirement.html") if {
	some name in resources_of_type("AWS::Batch::JobDefinition")
	cp := _pf_batch_cp(name)
	not _pf_batch_ohas(cp, "Vcpus")
	not _pf_batch_rr(cp, "VCPU")
}
