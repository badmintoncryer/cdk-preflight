package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-ecs-service-platform-version-ec2", "ERROR", name,
	"Properties.PlatformVersion",
	"LaunchType is EC2 but PlatformVersion is set; CreateService fails with \"The platform version must be null when specifying an EC2 launch type\"",
	"Remove PlatformVersion (it applies to Fargate only)",
	"https://docs.aws.amazon.com/AmazonECS/latest/APIReference/API_CreateService.html") if {
	some name in resources_of_type("AWS::ECS::Service")
	resolve(name, "Properties.LaunchType") == "EC2"
	props := input.resources[name].properties
	is_object(props)
	not object.get(props, "PlatformVersion", "__pf_absent") == "__pf_absent"
}
