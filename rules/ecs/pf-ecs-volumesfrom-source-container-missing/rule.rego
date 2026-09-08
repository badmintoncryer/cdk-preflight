package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-ecs-volumesfrom-source-container-missing", "ERROR", name,
	sprintf("Properties.ContainerDefinitions.%d.VolumesFrom", [c.index]),
	sprintf("Container '%s' takes volumes from '%s', which is not declared in this task definition; RegisterTaskDefinition fails with \"Invalid 'volumesFrom' setting. Unknown container: '%s'\"", [_pf_ecs_cname(c), sc, sc]),
	"Point SourceContainer at a container declared in the same task definition",
	"https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task_definition_parameters.html") if {
	some name in resources_of_type("AWS::ECS::TaskDefinition")
	some c in _pf_ecs_containers(name)
	vf := _pf_ecs_cget(c, "VolumesFrom")
	is_array(vf)
	some v in vf
	sc := object.get(v, "SourceContainer", null)
	_pf_ecs_lit(sc)
	not sc in _pf_ecs_names(name)
}
