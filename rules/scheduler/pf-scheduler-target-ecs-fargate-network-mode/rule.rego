package cdk_preflight

import rego.v1

# Same constraint as pf-events-target-ecs-fargate-network-mode, for EventBridge
# Scheduler: CreateSchedule does not open the task definition, so a FARGATE
# target whose task definition is not awsvpc deploys and then every invocation
# fails to start the task. An absent NetworkMode is bridge.
_pf_schfnm_mode(td) := m if {
	props := input.resources[td].properties
	is_object(props)
	m := object.get(props, "NetworkMode", "bridge")
	is_string(m)
}

violation contains make_diag_full("pf-scheduler-target-ecs-fargate-network-mode", "ERROR", name,
	"Properties.Target.EcsParameters.LaunchType",
	sprintf("The schedule starts task definition %s on FARGATE, but its NetworkMode is '%s'; Fargate only runs awsvpc tasks, so every invocation fails to start the task", [td, mode]),
	sprintf("Set NetworkMode: awsvpc on %s, or use the EC2 launch type", [td]),
	"https://docs.aws.amazon.com/AmazonECS/latest/developerguide/fargate-tasks-services.html#fargate-tasks-networking") if {
	some name in resources_of_type("AWS::Scheduler::Schedule")
	t := input.resources[name].properties.Target
	is_object(t)
	p := object.get(t, "EcsParameters", null)
	is_object(p)
	object.get(p, "LaunchType", null) == "FARGATE"
	ref := object.get(p, "TaskDefinitionArn", null)
	is_object(ref)
	td := object.get(ref, "__ref", null)
	td in resources_of_type("AWS::ECS::TaskDefinition")
	mode := _pf_schfnm_mode(td)
	mode != "awsvpc"
}
