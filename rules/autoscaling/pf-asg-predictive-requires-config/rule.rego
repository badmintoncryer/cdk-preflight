package cdk_preflight

import rego.v1

_pf_asgprc_url := "https://docs.aws.amazon.com/autoscaling/ec2/APIReference/API_PutScalingPolicy.html"

violation contains make_diag_full("pf-asg-predictive-requires-config", "ERROR", name,
	"Properties.PredictiveScalingConfiguration",
	"a PredictiveScaling policy has no PredictiveScalingConfiguration; the policy create fails with \"You must specify PredictiveScalingConfiguration\"",
	"Add PredictiveScalingConfiguration with one MetricSpecifications entry", _pf_asgprc_url) if {
	some name in resources_of_type("AWS::AutoScaling::ScalingPolicy")
	_pf_aslib_ptype(name) == "PredictiveScaling"
	_pf_aslib_absent(name, "PredictiveScalingConfiguration")
}
