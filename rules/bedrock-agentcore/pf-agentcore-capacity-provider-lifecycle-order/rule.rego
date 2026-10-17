package cdk_preflight

import rego.v1

# Both fields carry 60..1209600 in the schema; only CreateCapacityProvider
# orders them ("maxLifetime must be greater than or equal to
# idleInstanceTimeout"). Equal values are accepted.
violation contains make_diag_full("pf-agentcore-capacity-provider-lifecycle-order", "ERROR", name,
	"Properties.ComputeConfiguration.Ec2Configuration.LifecycleConfiguration.IdleInstanceTimeout",
	sprintf("IdleInstanceTimeout (%v) exceeds MaxLifetime (%v); CreateCapacityProvider fails with \"maxLifetime must be greater than or equal to idleInstanceTimeout\"", [idle, mx]),
	"Lower IdleInstanceTimeout to at most MaxLifetime, or raise MaxLifetime",
	"https://docs.aws.amazon.com/bedrock-agentcore-control/latest/APIReference/API_CreateCapacityProvider.html") if {
	some name in resources_of_type("AWS::BedrockAgentCore::CapacityProvider")
	idle := to_number(resolve(name, "Properties.ComputeConfiguration.Ec2Configuration.LifecycleConfiguration.IdleInstanceTimeout"))
	mx := to_number(resolve(name, "Properties.ComputeConfiguration.Ec2Configuration.LifecycleConfiguration.MaxLifetime"))
	idle > mx
}
