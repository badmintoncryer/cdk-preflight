package cdk_preflight

import rego.v1

_pf_asgttpm_url := "https://docs.aws.amazon.com/autoscaling/ec2/APIReference/API_PutScalingPolicy.html"

violation contains make_diag_full("pf-asg-tt-period-max-60", "ERROR", name,
	"Properties.TargetTrackingConfiguration.CustomizedMetricSpecification.Period",
	sprintf("Period %v is over 60 seconds; target tracking needs high-resolution data and the policy create fails with \"A metric period greater than 60 isn't supported\"", [n]),
	"Use a Period of 10, 30 or 60", _pf_asgttpm_url) if {
	some name in resources_of_type("AWS::AutoScaling::ScalingPolicy")
	n := _pf_aslib_num(name, "Properties.TargetTrackingConfiguration.CustomizedMetricSpecification.Period")
	n > 60
}
