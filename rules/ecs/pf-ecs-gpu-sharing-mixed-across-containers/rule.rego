package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-ecs-gpu-sharing-mixed-across-containers", "ERROR", name,
	"Properties.ContainerDefinitions[].ResourceRequirements[]",
	"One container requests GPUs by Value and another by SharingStrategy; the task definition create fails with \"A task cannot mix 'value' and 'sharingStrategy' across containers\"",
	"Use SharingStrategy on every GPU container, or Value on every GPU container",
	"https://docs.aws.amazon.com/AmazonECS/latest/developerguide/ecs-gpu.html") if {
	some name in resources_of_type("AWS::ECS::TaskDefinition")
	reqs := _pf_gpumix_reqs(name)
	some a in reqs
	object.get(a, "SharingStrategy", null) != null
	object.get(a, "Value", null) == null
	some b in reqs
	object.get(b, "Value", null) != null
	object.get(b, "SharingStrategy", null) == null
}

_pf_gpumix_reqs(name) := [r |
	some c in flatten_list(name, "Properties.ContainerDefinitions")
	is_object(c.value)
	reqs := object.get(c.value, "ResourceRequirements", [])
	is_array(reqs)
	some r in reqs
	is_object(r)
	r.Type == "GPU"
]
