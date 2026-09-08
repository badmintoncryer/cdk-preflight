package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-ecs-efs-access-point-with-root-directory", "ERROR", name,
	sprintf("Properties.Volumes.%d.EFSVolumeConfiguration.RootDirectory", [v.index]),
	sprintf("An EFS volume combines an access point with RootDirectory '%s'; RegisterTaskDefinition fails with \"When using an EFS access point, the root directory must either be set to \"/\" or be omitted\"", [rd]),
	"Drop RootDirectory (or set it to \"/\") when AccessPointId is used",
	"https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task_definition_parameters.html") if {
	some name in resources_of_type("AWS::ECS::TaskDefinition")
	some v in flatten_list(name, "Properties.Volumes")
	e := _pf_ecs_oget(v.value, "EFSVolumeConfiguration")
	ac := _pf_ecs_oget(e, "AuthorizationConfig")
	_pf_ecs_ohas(ac, "AccessPointId")
	rd := _pf_ecs_oget(e, "RootDirectory")
	_pf_ecs_lit(rd)
	rd != "/"
}
