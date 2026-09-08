package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-ecs-taskset-platform-version-ec2", "ERROR", name,
	"Properties.PlatformVersion",
	"The task set combines the EC2 launch type with a PlatformVersion; CreateTaskSet fails with \"The platform version must be null when specifying an EC2 launch type\"",
	"Drop PlatformVersion, or use the FARGATE launch type",
	"https://docs.aws.amazon.com/AmazonECS/latest/APIReference/API_CreateTaskSet.html") if {
	some name in resources_of_type("AWS::ECS::TaskSet")
	resolve(name, "Properties.LaunchType") == "EC2"
	_pf_ecs_has(name, "PlatformVersion")
}
