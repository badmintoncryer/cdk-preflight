package cdk_preflight

import rego.v1

# A Fargate task can only use the awsvpc network mode. PutTargets does not open
# the task definition, so a FARGATE target whose task definition uses another
# mode deploys and then every event fails to start a task. A task definition
# that declares FARGATE in RequiresCompatibilities is already checked for awsvpc
# when it is created; this is the EC2-only (or undeclared) one, which bench showed
# Fargate runs as long as it is awsvpc. An absent NetworkMode is bridge.
_pf_evfnm_mode(td) := m if {
	props := input.resources[td].properties
	is_object(props)
	m := object.get(props, "NetworkMode", "bridge")
	is_string(m)
}

violation contains make_diag_full("pf-events-target-ecs-fargate-network-mode", "ERROR", name,
	sprintf("Properties.Targets.%d.EcsParameters.LaunchType", [i]),
	sprintf("Target '%s' starts task definition %s on FARGATE, but its NetworkMode is '%s'; Fargate only runs awsvpc tasks, so every event fails to start the task", [object.get(t, "Id", "<target>"), td, mode]),
	sprintf("Set NetworkMode: awsvpc on %s, or use the EC2 launch type", [td]),
	"https://docs.aws.amazon.com/AmazonECS/latest/developerguide/fargate-tasks-services.html#fargate-tasks-networking") if {
	some name in resources_of_type("AWS::Events::Rule")
	props := input.resources[name].properties
	is_object(props)
	ts := object.get(props, "Targets", null)
	is_array(ts)
	some i, t in ts
	is_object(t)
	p := object.get(t, "EcsParameters", null)
	is_object(p)
	object.get(p, "LaunchType", null) == "FARGATE"
	ref := object.get(p, "TaskDefinitionArn", null)
	is_object(ref)
	td := object.get(ref, "__ref", null)
	td in resources_of_type("AWS::ECS::TaskDefinition")
	mode := _pf_evfnm_mode(td)
	mode != "awsvpc"
}
