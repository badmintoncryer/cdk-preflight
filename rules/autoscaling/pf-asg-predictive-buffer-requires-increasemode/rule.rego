package cdk_preflight

import rego.v1

_pf_asgpbi_url := "https://docs.aws.amazon.com/autoscaling/ec2/APIReference/API_PutScalingPolicy.html"

violation contains make_diag_full("pf-asg-predictive-buffer-requires-increasemode", "ERROR", name,
	"Properties.PredictiveScalingConfiguration.MaxCapacityBuffer",
	"MaxCapacityBreachBehavior is IncreaseMaxCapacity but no MaxCapacityBuffer says by how much; the policy create fails with \"You must specify max capacity buffer when using IncreaseMaxCapacity\"",
	"Set MaxCapacityBuffer to the percentage the forecast may exceed MaxSize by", _pf_asgpbi_url) if {
	some name in resources_of_type("AWS::AutoScaling::ScalingPolicy")
	resolve(name, "Properties.PredictiveScalingConfiguration.MaxCapacityBreachBehavior") == "IncreaseMaxCapacity"
	_pf_aslib_absent_at(name, ["PredictiveScalingConfiguration", "MaxCapacityBuffer"])
}
