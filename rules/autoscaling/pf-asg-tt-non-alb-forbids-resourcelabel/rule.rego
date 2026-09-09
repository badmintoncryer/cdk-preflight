package cdk_preflight

import rego.v1

_pf_asgttnr_url := "https://docs.aws.amazon.com/autoscaling/ec2/APIReference/API_PutScalingPolicy.html"

violation contains make_diag_full("pf-asg-tt-non-alb-forbids-resourcelabel", "ERROR", name,
	"Properties.TargetTrackingConfiguration.PredefinedMetricSpecification.ResourceLabel",
	sprintf("ResourceLabel is set for PredefinedMetricType %s; only ALBRequestCountPerTarget takes one, and the policy create fails with \"Resource label should not be specified for predefined metric type %s\"", [t, t]),
	"Remove ResourceLabel, or switch to ALBRequestCountPerTarget", _pf_asgttnr_url) if {
	some name in resources_of_type("AWS::AutoScaling::ScalingPolicy")
	t := resolve(name, "Properties.TargetTrackingConfiguration.PredefinedMetricSpecification.PredefinedMetricType")
	_pf_aslib_lit(t)
	t != "ALBRequestCountPerTarget"
	not _pf_aslib_absent_at(name, ["TargetTrackingConfiguration", "PredefinedMetricSpecification", "ResourceLabel"])
}
