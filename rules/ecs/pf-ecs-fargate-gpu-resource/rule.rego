package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-ecs-fargate-gpu-resource", "ERROR", name,
	sprintf("Properties.ContainerDefinitions.%d.ResourceRequirements", [c.index]),
	sprintf("Container '%s' requires a GPU on a FARGATE task definition; RegisterTaskDefinition fails with \"Tasks using the Fargate launch type do not support GPU resource requirements\"", [_pf_ecs_cname(c)]),
	"Drop the GPU ResourceRequirement, or run the task on EC2 with GPU instances",
	"https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task_definition_parameters.html") if {
	some name in resources_of_type("AWS::ECS::TaskDefinition")
	_pf_ecs_fargate(name)
	some c in _pf_ecs_containers(name)
	rr := _pf_ecs_cget(c, "ResourceRequirements")
	is_array(rr)
	some r in rr
	object.get(r, "Type", null) == "GPU"
}
