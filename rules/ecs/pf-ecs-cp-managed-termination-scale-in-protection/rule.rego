package cdk_preflight

import rego.v1

# The Auto Scaling group protects new instances from scale-in (CloudFormation
# accepts the boolean either as true or as the string "true").
_pf_ecs_scalein(props) if {
	object.get(props, "NewInstancesProtectedFromScaleIn", false) in {true, "true"}
}

violation contains make_diag_full("pf-ecs-cp-managed-termination-scale-in-protection", "ERROR", name,
	"Properties.AutoScalingGroupProvider.ManagedTerminationProtection",
	sprintf("ManagedTerminationProtection is ENABLED but the Auto Scaling group '%s' does not protect new instances from scale-in; CreateCapacityProvider fails with \"To enable managed termination protection for a capacity provider, the Auto Scaling group must have instance protection from scale-in enabled\"", [g]),
	"Set NewInstancesProtectedFromScaleIn on the Auto Scaling group, or drop ManagedTerminationProtection",
	"https://docs.aws.amazon.com/AmazonECS/latest/APIReference/API_CreateCapacityProvider.html") if {
	some name in resources_of_type("AWS::ECS::CapacityProvider")
	asg := _pf_ecs_get(name, "AutoScalingGroupProvider")
	_pf_ecs_oget(asg, "ManagedTerminationProtection") == "ENABLED"
	g := resolve(name, "Properties.AutoScalingGroupProvider.AutoScalingGroupArn")
	input.resources[g].resourceType == "AWS::AutoScaling::AutoScalingGroup"
	not _pf_ecs_scalein(input.resources[g].properties)
}
