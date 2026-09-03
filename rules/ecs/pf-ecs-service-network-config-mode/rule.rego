package cdk_preflight

import rego.v1

# The engine ships E3052 for the inverse (awsvpc task definition without
# NetworkConfiguration); this direction is unguarded. Only an explicit
# non-awsvpc NetworkMode fires - the absent-mode default is unbenched.
violation contains make_diag_full("pf-ecs-service-network-config-mode", "ERROR", name,
	"Properties.NetworkConfiguration",
	sprintf("NetworkConfiguration is set but the referenced task definition uses NetworkMode '%s'; CreateService fails with \"Network Configuration is not valid for the given networkMode of this task definition.\"", [nm]),
	"Use an awsvpc task definition, or drop NetworkConfiguration",
	"https://docs.aws.amazon.com/AmazonECS/latest/APIReference/API_CreateService.html") if {
	some name in resources_of_type("AWS::ECS::Service")
	props := input.resources[name].properties
	is_object(props)
	not object.get(props, "NetworkConfiguration", "__pf_absent") == "__pf_absent"
	td := resolve(name, "Properties.TaskDefinition")
	td in resources_of_type("AWS::ECS::TaskDefinition")
	nm := resolve(td, "Properties.NetworkMode")
	is_string(nm)
	nm != "awsvpc"
}
