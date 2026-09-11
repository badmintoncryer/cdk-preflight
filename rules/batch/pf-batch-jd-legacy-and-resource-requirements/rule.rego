package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-batch-jd-legacy-and-resource-requirements", "ERROR", name,
	"Properties.ContainerProperties.ResourceRequirements",
	sprintf("ContainerProperties sets both %v and a %v resource requirement (\"Cannot use both ECS containerProperties %v and resourceRequirement %v.\")", [p[0], p[1], p[0], p[1]]),
	"Drop the legacy field and keep ResourceRequirements",
	"https://docs.aws.amazon.com/batch/latest/APIReference/API_ContainerProperties.html") if {
	some name in resources_of_type("AWS::Batch::JobDefinition")
	cp := _pf_batch_cp(name)
	some p in [["Vcpus", "VCPU"], ["Memory", "MEMORY"]]
	_pf_batch_ohas(cp, p[0])
	_pf_batch_rr(cp, p[1])
}
