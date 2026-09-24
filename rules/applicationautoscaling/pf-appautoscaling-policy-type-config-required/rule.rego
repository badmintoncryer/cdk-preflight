package cdk_preflight

import rego.v1

_pf_aascfgreq_block := {
	"StepScaling": "StepScalingPolicyConfiguration",
	"TargetTrackingScaling": "TargetTrackingScalingPolicyConfiguration",
	"PredictiveScaling": "PredictiveScalingPolicyConfiguration",
}

violation contains make_diag_full("pf-appautoscaling-policy-type-config-required", "ERROR", name,
	"Properties.PolicyType",
	sprintf("PolicyType '%s' but no %s; PutScalingPolicy fails with \"%s policy configuration must be specified\"", [pt, block, pt]),
	sprintf("Add a %s, or change PolicyType to the one the policy actually configures", [block]),
	"https://docs.aws.amazon.com/autoscaling/application/APIReference/API_PutScalingPolicy.html") if {
	some name in resources_of_type("AWS::ApplicationAutoScaling::ScalingPolicy")
	pt := resolve(name, "Properties.PolicyType")
	block := _pf_aascfgreq_block[pt]
	not _pf_aaslib_has(name, block)
}
