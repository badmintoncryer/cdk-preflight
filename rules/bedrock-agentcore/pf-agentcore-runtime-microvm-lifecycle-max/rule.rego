package cdk_preflight

import rego.v1

# The schema allows 1209600 seconds, the Instances runtime limit. A microVM
# runtime (no CapacityProviderConfiguration) is capped at 28800:
# CreateAgentRuntime fails with "maxLifeTime must be less than or equal to
# 28800 seconds". IdleRuntimeSessionTimeout is not checked: above 28800 it
# would also exceed MaxLifetime, which pf-agentcore-runtime-lifecycle-timeout-
# order covers.
violation contains make_diag_full("pf-agentcore-runtime-microvm-lifecycle-max", "ERROR", name,
	"Properties.LifecycleConfiguration.MaxLifetime",
	sprintf("MaxLifetime %v exceeds 28800 for a runtime without a capacity provider; CreateAgentRuntime fails with \"maxLifeTime must be less than or equal to 28800 seconds\"", [m]),
	"Lower MaxLifetime to 28800 or less, or run the agent on a capacity provider",
	"https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/runtime-lifecycle-settings.html") if {
	some name in resources_of_type("AWS::BedrockAgentCore::Runtime")
	not _pf_acrt_has_cp(name)
	m := resolve(name, "Properties.LifecycleConfiguration.MaxLifetime")
	is_number(m)
	m > 28800
}
