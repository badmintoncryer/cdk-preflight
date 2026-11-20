package cdk_preflight

import rego.v1

# Same ordering as pf-agentcore-runtime-lifecycle-timeout-order, at the place
# the 2026-11 schema added it on Harness
# (Environment.AgentCoreRuntimeEnvironment.LifecycleConfiguration). The schema
# text says "must be less than or equal to MaxLifetime"; the engine checks only
# each field's range.
violation contains make_diag_full("pf-agentcore-harness-lifecycle-timeout-order", "ERROR", name,
	"Properties.Environment.AgentCoreRuntimeEnvironment.LifecycleConfiguration.IdleRuntimeSessionTimeout",
	sprintf("IdleRuntimeSessionTimeout (%v) exceeds MaxLifetime (%v); the harness create fails", [idle, max_lifetime]),
	"Lower IdleRuntimeSessionTimeout to at most MaxLifetime, or raise MaxLifetime",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-bedrockagentcore-harness-lifecycleconfiguration.html") if {
	some name in resources_of_type("AWS::BedrockAgentCore::Harness")
	idle := _pf_num(name, "Properties.Environment.AgentCoreRuntimeEnvironment.LifecycleConfiguration.IdleRuntimeSessionTimeout")
	max_lifetime := _pf_num(name, "Properties.Environment.AgentCoreRuntimeEnvironment.LifecycleConfiguration.MaxLifetime")
	idle > max_lifetime
}
