package cdk_preflight

import rego.v1

_pf_asgttme_url := "https://docs.aws.amazon.com/autoscaling/ec2/APIReference/API_PutScalingPolicy.html"

_pf_asgttme_fix := "Keep either PredefinedMetricSpecification or CustomizedMetricSpecification, not both and not neither"

violation contains make_diag_full("pf-asg-tt-metric-spec-exclusive", "ERROR", name,
	"Properties.TargetTrackingConfiguration.CustomizedMetricSpecification",
	"the configuration sets both CustomizedMetricSpecification and PredefinedMetricSpecification; the policy create fails with \"You should provide either a CustomizedMetricSpecification or a PredefinedMetricSpecification\"",
	_pf_asgttme_fix, _pf_asgttme_url) if {
	some name in resources_of_type("AWS::AutoScaling::ScalingPolicy")
	not _pf_aslib_absent_at(name, ["TargetTrackingConfiguration", "CustomizedMetricSpecification"])
	not _pf_aslib_absent_at(name, ["TargetTrackingConfiguration", "PredefinedMetricSpecification"])
}

violation contains make_diag_full("pf-asg-tt-metric-spec-exclusive", "ERROR", name,
	"Properties.TargetTrackingConfiguration",
	"the configuration sets neither CustomizedMetricSpecification nor PredefinedMetricSpecification; the policy create fails with \"You should provide either a CustomizedMetricSpecification or a PredefinedMetricSpecification\"",
	_pf_asgttme_fix, _pf_asgttme_url) if {
	some name in resources_of_type("AWS::AutoScaling::ScalingPolicy")
	_pf_aslib_obj(name, ["TargetTrackingConfiguration"])
	_pf_aslib_absent_at(name, ["TargetTrackingConfiguration", "CustomizedMetricSpecification"])
	_pf_aslib_absent_at(name, ["TargetTrackingConfiguration", "PredefinedMetricSpecification"])
}
