package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-ecs-efs-transit-encryption-port-without-encryption", "ERROR", name,
	sprintf("Properties.Volumes.%d.EFSVolumeConfiguration.TransitEncryptionPort", [v.index]),
	"An EFS volume pins a transit encryption port without enabling transit encryption; RegisterTaskDefinition fails with \"TransitEncryptionPort requires that TransitEncryption is enabled\"",
	"Set TransitEncryption to ENABLED, or drop TransitEncryptionPort",
	"https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task_definition_parameters.html") if {
	some name in resources_of_type("AWS::ECS::TaskDefinition")
	some v in flatten_list(name, "Properties.Volumes")
	e := _pf_ecs_oget(v.value, "EFSVolumeConfiguration")
	_pf_ecs_ohas(e, "TransitEncryptionPort")
	not _pf_ecs_oget(e, "TransitEncryption") == "ENABLED"
}
