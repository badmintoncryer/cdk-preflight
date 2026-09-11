package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-batch-jd-resource-requirements-duplicate-type", "ERROR", name,
	"Properties.ContainerProperties.ResourceRequirements",
	sprintf("ResourceRequirements lists %v %v times (\"Cannot provide duplicates in resourceRequirements.\")", [t, n]),
	"Keep one entry per resource type",
	"https://docs.aws.amazon.com/batch/latest/APIReference/API_ResourceRequirement.html") if {
	some name in resources_of_type("AWS::Batch::JobDefinition")
	cp := _pf_batch_cp(name)
	some t in {"VCPU", "MEMORY", "GPU"}
	n := count([1 | some e in object.get(cp, "ResourceRequirements", []); is_object(e); object.get(e, "Type", "") == t])
	n > 1
}
