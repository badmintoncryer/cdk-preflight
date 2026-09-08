package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-ecs-cp-scaling-step-order", "ERROR", name,
	"Properties.AutoScalingGroupProvider.ManagedScaling",
	sprintf("ManagedScaling sets MinimumScalingStepSize %v above MaximumScalingStepSize %v; CreateCapacityProvider fails with \"The minimum or maximum scaling step size value is invalid\"", [mn, mx]),
	"Lower MinimumScalingStepSize to at most MaximumScalingStepSize",
	"https://docs.aws.amazon.com/AmazonECS/latest/APIReference/API_CreateCapacityProvider.html") if {
	some name in resources_of_type("AWS::ECS::CapacityProvider")
	asg := _pf_ecs_get(name, "AutoScalingGroupProvider")
	ms := _pf_ecs_oget(asg, "ManagedScaling")
	mn := to_number(_pf_ecs_oget(ms, "MinimumScalingStepSize"))
	mx := to_number(_pf_ecs_oget(ms, "MaximumScalingStepSize"))
	mn > mx
}
