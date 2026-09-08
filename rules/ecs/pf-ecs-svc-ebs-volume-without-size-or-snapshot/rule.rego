package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-ecs-svc-ebs-volume-without-size-or-snapshot", "ERROR", name,
	"Properties.VolumeConfigurations",
	"A ManagedEBSVolume sets neither SizeInGiB nor SnapshotId; CreateService fails with \"ECS managed EBS volume configuration was invalid\" (MissingParameter)",
	"Set SizeInGiB, or restore from SnapshotId",
	"https://docs.aws.amazon.com/AmazonECS/latest/developerguide/service_definition_parameters.html") if {
	some name in resources_of_type("AWS::ECS::Service")
	some v in flatten_list(name, "Properties.VolumeConfigurations")
	eb := _pf_ecs_oget(v.value, "ManagedEBSVolume")
	not _pf_ecs_ohas(eb, "SizeInGiB")
	not _pf_ecs_ohas(eb, "SnapshotId")
}
