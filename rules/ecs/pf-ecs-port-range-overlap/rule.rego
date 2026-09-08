package cdk_preflight

import rego.v1

# Numeric bounds of a "<low>-<high>" container port range.
_pf_ecs_range(pm) := [lo, hi] if {
	r := object.get(pm, "ContainerPortRange", null)
	_pf_ecs_lit(r)
	parts := split(r, "-")
	count(parts) == 2
	lo := to_number(parts[0])
	hi := to_number(parts[1])
}

violation contains make_diag_full("pf-ecs-port-range-overlap", "ERROR", name,
	"Properties.ContainerDefinitions",
	sprintf("The container port ranges %v and %v overlap; RegisterTaskDefinition fails with \"container port is used multiple times in task\"", [a, b]),
	"Make the container port ranges disjoint",
	"https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task_definition_parameters.html") if {
	some name in resources_of_type("AWS::ECS::TaskDefinition")
	pms := _pf_ecs_portmappings(name)
	some i, j
	i < j
	a := _pf_ecs_range(pms[i])
	b := _pf_ecs_range(pms[j])
	a[0] <= b[1]
	b[0] <= a[1]
}
