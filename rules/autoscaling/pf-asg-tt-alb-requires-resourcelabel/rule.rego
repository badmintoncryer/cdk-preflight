package cdk_preflight

import rego.v1

_pf_asgttar_url := "https://docs.aws.amazon.com/autoscaling/ec2/APIReference/API_PutScalingPolicy.html"

violation contains make_diag_full("pf-asg-tt-alb-requires-resourcelabel", "ERROR", name,
	"Properties.TargetTrackingConfiguration.PredefinedMetricSpecification.ResourceLabel",
	"PredefinedMetricType is ALBRequestCountPerTarget but no ResourceLabel names the target group; the policy create fails with \"Resource label should be specified for predefined metric type ALBRequestCountPerTarget\"",
	"Set ResourceLabel to app/<lb>/<lb-id>/targetgroup/<tg>/<tg-id>", _pf_asgttar_url) if {
	some name in resources_of_type("AWS::AutoScaling::ScalingPolicy")
	resolve(name, "Properties.TargetTrackingConfiguration.PredefinedMetricSpecification.PredefinedMetricType") == "ALBRequestCountPerTarget"
	_pf_aslib_absent_at(name, ["TargetTrackingConfiguration", "PredefinedMetricSpecification", "ResourceLabel"])
}
