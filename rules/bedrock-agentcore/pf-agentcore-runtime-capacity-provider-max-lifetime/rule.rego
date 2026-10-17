package cdk_preflight

import rego.v1

# An Instances runtime session cannot outlive the instance. The runtime and
# the capacity provider both default MaxLifetime to 28800, so a capacity
# provider with a shorter MaxLifetime rejects a runtime that leaves
# LifecycleConfiguration out ("maxLifeTime must be less than or equal to the
# CapacityProvider instance maxLifetime (3600 seconds)"). Checked only when
# the capacity provider is in the same template.
violation contains make_diag_full("pf-agentcore-runtime-capacity-provider-max-lifetime", "ERROR", name,
	"Properties.LifecycleConfiguration.MaxLifetime",
	sprintf("MaxLifetime %v exceeds capacity provider '%s' MaxLifetime %v (an omitted value is 28800); CreateAgentRuntime fails with \"maxLifeTime must be less than or equal to the CapacityProvider instance maxLifetime\"", [rt, cp, cpmax]),
	"Set LifecycleConfiguration.MaxLifetime to at most the capacity provider's MaxLifetime",
	"https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/runtime-lifecycle-settings.html") if {
	some name in resources_of_type("AWS::BedrockAgentCore::Runtime")
	cp := _pf_acrt_cp(name)
	cpmax := _pf_acrt_num(cp, "Properties.ComputeConfiguration.Ec2Configuration.LifecycleConfiguration.MaxLifetime", 28800)
	rt := _pf_acrt_num(name, "Properties.LifecycleConfiguration.MaxLifetime", 28800)
	rt > cpmax
}
