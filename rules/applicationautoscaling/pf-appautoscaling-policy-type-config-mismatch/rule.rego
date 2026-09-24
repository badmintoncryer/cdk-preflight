package cdk_preflight

import rego.v1

_pf_aascfgmis_block := {
	"StepScaling": "StepScalingPolicyConfiguration",
	"TargetTrackingScaling": "TargetTrackingScalingPolicyConfiguration",
	"PredictiveScaling": "PredictiveScalingPolicyConfiguration",
}

# Only when the matching block is there too. A policy that carries just the wrong
# block reads to the service as a missing configuration, which is
# pf-appautoscaling-policy-type-config-required's message, so the two rules
# partition the cases exactly as the service's two errors do.
violation contains make_diag_full("pf-appautoscaling-policy-type-config-mismatch", "ERROR", name,
	"Properties.PolicyType",
	sprintf("PolicyType '%s' also carries %s; PutScalingPolicy fails with \"You must only provide a single scaling policy configuration, which must match the scaling policy type specified.\"", [pt, extra]),
	sprintf("Drop %s, or split the policy in two so each PolicyType has its own resource", [extra]),
	"https://docs.aws.amazon.com/autoscaling/application/APIReference/API_PutScalingPolicy.html") if {
	some name in resources_of_type("AWS::ApplicationAutoScaling::ScalingPolicy")
	pt := resolve(name, "Properties.PolicyType")
	_pf_aaslib_has(name, _pf_aascfgmis_block[pt])
	some other, extra in _pf_aascfgmis_block
	other != pt
	_pf_aaslib_has(name, extra)
}
