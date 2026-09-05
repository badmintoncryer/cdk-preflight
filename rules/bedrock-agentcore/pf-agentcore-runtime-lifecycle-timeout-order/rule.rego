package cdk_preflight

import rego.v1

# Both fields carry the same 60..1209600 range in the schema; the ordering
# between them is enforced only by CreateAgentRuntime
# ("idleRuntimeSessionTimeout must be less than or equal to maxLifeTime",
# measured 2026-09-06).
violation contains make_diag_full("pf-agentcore-runtime-lifecycle-timeout-order", "ERROR", name,
	"Properties.LifecycleConfiguration.IdleRuntimeSessionTimeout",
	sprintf("IdleRuntimeSessionTimeout (%v) exceeds MaxLifetime (%v); CreateAgentRuntime fails with \"idleRuntimeSessionTimeout must be less than or equal to maxLifeTime\"", [idle, max_lifetime]),
	"Lower IdleRuntimeSessionTimeout to at most MaxLifetime, or raise MaxLifetime",
	"https://docs.aws.amazon.com/bedrock-agentcore-control/latest/APIReference/API_LifecycleConfiguration.html") if {
	some name in resources_of_type("AWS::BedrockAgentCore::Runtime")
	idle := to_number(resolve(name, "Properties.LifecycleConfiguration.IdleRuntimeSessionTimeout"))
	max_lifetime := to_number(resolve(name, "Properties.LifecycleConfiguration.MaxLifetime"))
	idle > max_lifetime
}
