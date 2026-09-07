package cdk_preflight

import rego.v1

# EcsParameters carries a launch-type-dependent set of options and two
# hard size caps. Every case measured 2026-09-07 via events:PutTargets in
# us-east-1, each with a passing control: 16 subnets and 5 security groups
# deploy, 17 and 6 do not; TaskCount 1-10 deploys, 11 does not.
# CapacityProviderStrategy alongside LaunchType and a distinctInstance
# constraint carrying an expression are BOTH accepted, so neither is reported.
_pf_evecs_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-events-rule-ecsparameters.html"

_pf_evecs_targets(name) := [t |
	some t in flatten_list(name, "Properties.Targets")
	is_object(t.value)
	is_object(object.get(t.value, "EcsParameters", null))
]

_pf_evecs_params(t) := t.value.EcsParameters

_pf_evecs_awsvpc(p) := v if {
	nc := object.get(p, "NetworkConfiguration", null)
	is_object(nc)
	v := object.get(nc, "AwsVpcConfiguration", null)
	is_object(v)
}

violation contains make_diag_full("pf-events-target-ecs-parameters", "ERROR", name,
	sprintf("Properties.Targets.%d.EcsParameters.NetworkConfiguration", [t.index]),
	sprintf("A FARGATE task needs a NetworkConfiguration; PutTargets fails with \"Parameter NetworkConfiguration must be specified for target %s when launch type is FARGATE\"", [tid]),
	"Add EcsParameters.NetworkConfiguration.AwsVpcConfiguration",
	_pf_evecs_url) if {
	some name in resources_of_type("AWS::Events::Rule")
	some t in _pf_evecs_targets(name)
	p := _pf_evecs_params(t)
	object.get(p, "LaunchType", null) == "FARGATE"
	object.get(p, "NetworkConfiguration", "__pf_absent") == "__pf_absent"
	tid := object.get(t.value, "Id", "<target>")
}

violation contains make_diag_full("pf-events-target-ecs-parameters", "ERROR", name,
	sprintf("Properties.Targets.%d.EcsParameters.PlatformVersion", [t.index]),
	sprintf("PlatformVersion is a Fargate setting; PutTargets fails with \"Parameter PlatformVersion for target %s is not supported when launch type is EC2\"", [tid]),
	"Drop PlatformVersion, or use the FARGATE launch type",
	_pf_evecs_url) if {
	some name in resources_of_type("AWS::Events::Rule")
	some t in _pf_evecs_targets(name)
	p := _pf_evecs_params(t)
	object.get(p, "LaunchType", null) == "EC2"
	object.get(p, "PlatformVersion", "__pf_absent") != "__pf_absent"
	tid := object.get(t.value, "Id", "<target>")
}

violation contains make_diag_full("pf-events-target-ecs-parameters", "ERROR", name,
	sprintf("Properties.Targets.%d.EcsParameters.NetworkConfiguration.AwsVpcConfiguration.AssignPublicIp", [t.index]),
	sprintf("AssignPublicIp is a Fargate setting; PutTargets fails with \"Parameter AssignPublicIp for target %s is not supported when launch type is EC2\"", [tid]),
	"Drop AssignPublicIp, or use the FARGATE launch type",
	_pf_evecs_url) if {
	some name in resources_of_type("AWS::Events::Rule")
	some t in _pf_evecs_targets(name)
	p := _pf_evecs_params(t)
	object.get(p, "LaunchType", null) == "EC2"
	object.get(_pf_evecs_awsvpc(p), "AssignPublicIp", "__pf_absent") != "__pf_absent"
	tid := object.get(t.value, "Id", "<target>")
}

violation contains make_diag_full("pf-events-target-ecs-parameters", "ERROR", name,
	sprintf("Properties.Targets.%d.EcsParameters.NetworkConfiguration.AwsVpcConfiguration.Subnets", [t.index]),
	sprintf("%d subnets are listed; PutTargets fails with \"Parameter Subnets is not valid. Reason: size must be in between 1 and 16\"", [count(subnets)]),
	"List at most 16 subnets",
	_pf_evecs_url) if {
	some name in resources_of_type("AWS::Events::Rule")
	some t in _pf_evecs_targets(name)
	subnets := object.get(_pf_evecs_awsvpc(_pf_evecs_params(t)), "Subnets", [])
	is_array(subnets)
	count(subnets) > 16
}

violation contains make_diag_full("pf-events-target-ecs-parameters", "ERROR", name,
	sprintf("Properties.Targets.%d.EcsParameters.NetworkConfiguration.AwsVpcConfiguration.SecurityGroups", [t.index]),
	sprintf("%d security groups are listed; PutTargets fails with \"Parameter SecurityGroups is not valid. Reason: size must be in between 0 and 5\"", [count(sgs)]),
	"List at most 5 security groups",
	_pf_evecs_url) if {
	some name in resources_of_type("AWS::Events::Rule")
	some t in _pf_evecs_targets(name)
	sgs := object.get(_pf_evecs_awsvpc(_pf_evecs_params(t)), "SecurityGroups", [])
	is_array(sgs)
	count(sgs) > 5
}

violation contains make_diag_full("pf-events-target-ecs-parameters", "ERROR", name,
	sprintf("Properties.Targets.%d.EcsParameters.TaskCount", [t.index]),
	sprintf("TaskCount %v is above the 10 a rule may launch; PutTargets fails with \"Parameter(s) TaskCount not valid for target: %s\"", [n, tid]),
	"Launch at most 10 tasks per event",
	_pf_evecs_url) if {
	some name in resources_of_type("AWS::Events::Rule")
	some t in _pf_evecs_targets(name)
	n := to_number(object.get(_pf_evecs_params(t), "TaskCount", "__pf_absent"))
	n > 10
	tid := object.get(t.value, "Id", "<target>")
}
