package cdk_preflight

import rego.v1

# The mounted volume names of the whole task definition.
_pf_ecs_mounted(name) := {sv |
	some c in _pf_ecs_containers(name)
	mps := _pf_ecs_cget(c, "MountPoints")
	is_array(mps)
	some mp in mps
	sv := object.get(mp, "SourceVolume", null)
}

violation contains make_diag_full("pf-ecs-volume-not-referenced", "ERROR", name,
	sprintf("Properties.Volumes.%d.Name", [v.index]),
	sprintf("The ConfiguredAtLaunch volume '%s' is declared but no container mounts it; RegisterTaskDefinition fails with \"Volumes [%s] are not referenced by any of the containers\"", [vn, vn]),
	"Add a MountPoint for the volume, or drop the volume",
	"https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task_definition_parameters.html") if {
	some name in resources_of_type("AWS::ECS::TaskDefinition")
	some v in flatten_list(name, "Properties.Volumes")
	object.get(v.value, "ConfiguredAtLaunch", false) == true
	vn := object.get(v.value, "Name", null)
	_pf_ecs_lit(vn)
	not vn in _pf_ecs_mounted(name)
}
