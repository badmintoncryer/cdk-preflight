package cdk_preflight

import rego.v1

_pf_asgpar_url := "https://docs.aws.amazon.com/autoscaling/ec2/APIReference/API_PutScalingPolicy.html"

_pf_asgpar_keys := ["PredefinedMetricPairSpecification", "PredefinedScalingMetricSpecification", "PredefinedLoadMetricSpecification"]

violation contains make_diag_full("pf-asg-predictive-alb-requires-resourcelabel", "ERROR", name,
	sprintf("Properties.PredictiveScalingConfiguration.MetricSpecifications.%d.%s.ResourceLabel", [i, k]),
	sprintf("%s is an Application Load Balancer metric but no ResourceLabel names the target group; the policy create fails with \"A resource label is required\"", [t]),
	"Set ResourceLabel to app/<lb>/<lb-id>/targetgroup/<tg>/<tg-id>", _pf_asgpar_url) if {
	some name in resources_of_type("AWS::AutoScaling::ScalingPolicy")
	some i, s in _pf_aslib_pmetrics(name)
	is_object(s)
	some k in _pf_asgpar_keys
	spec := object.get(s, k, null)
	is_object(spec)
	t := object.get(spec, "PredefinedMetricType", "")
	startswith(t, "ALB")
	object.get(spec, "ResourceLabel", "__pf_absent") == "__pf_absent"
}
