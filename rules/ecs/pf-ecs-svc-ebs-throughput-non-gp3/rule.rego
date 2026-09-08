package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-ecs-svc-ebs-throughput-non-gp3", "ERROR", name,
	"Properties.VolumeConfigurations",
	sprintf("A ManagedEBSVolume of type '%s' sets Throughput, which only gp3 supports; CreateService fails with \"ECS managed EBS volume configuration was invalid\" (InvalidParameterCombination)", [vt]),
	"Drop Throughput, or use VolumeType gp3",
	"https://docs.aws.amazon.com/AmazonECS/latest/developerguide/service_definition_parameters.html") if {
	some name in resources_of_type("AWS::ECS::Service")
	some v in flatten_list(name, "Properties.VolumeConfigurations")
	eb := _pf_ecs_oget(v.value, "ManagedEBSVolume")
	_pf_ecs_ohas(eb, "Throughput")
	vt := _pf_ecs_oget(eb, "VolumeType")
	_pf_ecs_lit(vt)
	vt != "gp3"
}
