package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-ecs-mountpoint-source-volume-missing", "ERROR", name,
	sprintf("Properties.ContainerDefinitions.%d.MountPoints", [c.index]),
	sprintf("Container '%s' mounts the volume '%s', which the task definition does not declare; RegisterTaskDefinition fails with \"Unknown volume '%s'\"", [_pf_ecs_cname(c), sv, sv]),
	"Declare the volume in Properties.Volumes, or point SourceVolume at an existing one",
	"https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task_definition_parameters.html") if {
	some name in resources_of_type("AWS::ECS::TaskDefinition")
	some c in _pf_ecs_containers(name)
	mps := _pf_ecs_cget(c, "MountPoints")
	is_array(mps)
	some mp in mps
	sv := object.get(mp, "SourceVolume", null)
	_pf_ecs_lit(sv)
	not sv in _pf_ecs_volnames(name)
}
