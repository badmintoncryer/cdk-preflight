package cdk_preflight

import rego.v1

_pf_asgpse_url := "https://docs.aws.amazon.com/autoscaling/ec2/APIReference/API_PutScalingPolicy.html"

violation contains make_diag_full("pf-asg-predictive-metricspecs-single-element", "ERROR", name,
	"Properties.PredictiveScalingConfiguration.MetricSpecifications",
	sprintf("MetricSpecifications holds %d entries; predictive scaling takes exactly one (the CloudFormation schema allows any size) and the policy create fails with \"You must specify one metric specification\"", [n]),
	"Keep a single MetricSpecifications entry", _pf_asgpse_url) if {
	some name in resources_of_type("AWS::AutoScaling::ScalingPolicy")
	n := count(_pf_aslib_pmetrics(name))
	n != 1
}
