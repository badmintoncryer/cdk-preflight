package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-ecs-svc-ebs-iops-unsupported-type", "ERROR", name,
	"Properties.VolumeConfigurations",
	sprintf("A ManagedEBSVolume of type '%s' sets Iops, which only io1, io2 and gp3 support; CreateService fails with \"ECS managed EBS volume configuration was invalid\" (InvalidParameterCombination)", [vt]),
	"Drop Iops, or use io1 / io2 / gp3",
	"https://docs.aws.amazon.com/AmazonECS/latest/developerguide/service_definition_parameters.html") if {
	some name in resources_of_type("AWS::ECS::Service")
	some v in flatten_list(name, "Properties.VolumeConfigurations")
	eb := _pf_ecs_oget(v.value, "ManagedEBSVolume")
	_pf_ecs_ohas(eb, "Iops")
	vt := _pf_ecs_oget(eb, "VolumeType")
	_pf_ecs_lit(vt)
	not vt in {"io1", "io2", "gp3"}
}
