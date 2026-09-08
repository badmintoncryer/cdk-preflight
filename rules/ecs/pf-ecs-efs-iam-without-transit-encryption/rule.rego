package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-ecs-efs-iam-without-transit-encryption", "ERROR", name,
	sprintf("Properties.Volumes.%d.EFSVolumeConfiguration.TransitEncryption", [v.index]),
	"An EFS volume uses IAM authorization without transit encryption; RegisterTaskDefinition fails with \"EFS IAM authorization requires TransitEncryption to be enabled\"",
	"Set EFSVolumeConfiguration.TransitEncryption to ENABLED",
	"https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task_definition_parameters.html") if {
	some name in resources_of_type("AWS::ECS::TaskDefinition")
	some v in flatten_list(name, "Properties.Volumes")
	e := _pf_ecs_oget(v.value, "EFSVolumeConfiguration")
	ac := _pf_ecs_oget(e, "AuthorizationConfig")
	_pf_ecs_oget(ac, "IAM") == "ENABLED"
	not _pf_ecs_oget(e, "TransitEncryption") == "ENABLED"
}
