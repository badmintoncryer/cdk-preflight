package cdk_preflight

import rego.v1

# GPU sharing (SharingStrategy) arrived in the 2026-10 schema; RegisterTaskDefinition
# rejects a GPU requirement that also sets Value. Engine 1.14.0 is clean on it.
violation contains make_diag_full("pf-ecs-gpu-value-sharing-exclusive", "ERROR", name,
	"Properties.ContainerDefinitions[].ResourceRequirements[]",
	"A GPU resource requirement sets both Value and SharingStrategy; the task definition create fails with \"Only one of 'value' or 'sharingStrategy' can be specified\"",
	"Set either Value (whole GPUs) or SharingStrategy (shared GPU), not both",
	"https://docs.aws.amazon.com/AmazonECS/latest/developerguide/ecs-gpu.html") if {
	some name in resources_of_type("AWS::ECS::TaskDefinition")
	some r in _pf_gpuvx_reqs(name)
	object.get(r, "Value", null) != null
	object.get(r, "SharingStrategy", null) != null
}

_pf_gpuvx_reqs(name) := [r |
	some c in flatten_list(name, "Properties.ContainerDefinitions")
	is_object(c.value)
	reqs := object.get(c.value, "ResourceRequirements", [])
	is_array(reqs)
	some r in reqs
	is_object(r)
	r.Type == "GPU"
]
