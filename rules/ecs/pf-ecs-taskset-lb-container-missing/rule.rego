package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-ecs-taskset-lb-container-missing", "ERROR", name,
	"Properties.LoadBalancers",
	sprintf("The task set targets the container '%s', which the referenced task definition does not declare; CreateTaskSet fails with \"The container %s does not exist in the task definition\"", [cn, cn]),
	"Point ContainerName at a container of the referenced task definition",
	"https://docs.aws.amazon.com/AmazonECS/latest/APIReference/API_CreateTaskSet.html") if {
	some name in resources_of_type("AWS::ECS::TaskSet")
	lbs := _pf_ecs_get(name, "LoadBalancers")
	is_array(lbs)
	some lb in lbs
	cn := object.get(lb, "ContainerName", null)
	_pf_ecs_lit(cn)
	td := _pf_ecs_reftd(name, "Properties.TaskDefinition")
	not cn in _pf_ecs_names(td)
}
