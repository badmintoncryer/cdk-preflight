package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-ecs-service-name", "ERROR", name,
	"Properties.ServiceName",
	sprintf("ServiceName '%s' is rejected by the service: letters, numbers, hyphen and underscore, at most 255 characters", [v]),
	"Rename it to satisfy letters, numbers, hyphen and underscore, at most 255 characters",
	"https://docs.aws.amazon.com/AmazonECS/latest/APIReference/API_CreateCluster.html") if {
	some name in resources_of_type("AWS::ECS::Service")
	v := resolve(name, "Properties.ServiceName")
	is_string(v)
	not regex.match(`^[a-zA-Z0-9_-]{1,255}$`, v)
}
