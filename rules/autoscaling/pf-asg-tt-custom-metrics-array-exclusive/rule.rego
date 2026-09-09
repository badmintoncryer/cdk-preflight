package cdk_preflight

import rego.v1

_pf_asgttcx_url := "https://docs.aws.amazon.com/autoscaling/ec2/APIReference/API_PutScalingPolicy.html"

_pf_asgttcx_simple := ["Dimensions", "MetricName", "Namespace", "Statistic", "Unit", "Period"]

violation contains make_diag_full("pf-asg-tt-custom-metrics-array-exclusive", "ERROR", name,
	sprintf("Properties.TargetTrackingConfiguration.CustomizedMetricSpecification.%s", [k]),
	sprintf("CustomizedMetricSpecification uses the Metrics (metric math) form, so %s cannot come with it; the policy create fails with \"A customized metric specification with 'Metrics' specified cannot have any of ['Dimensions', 'MetricName', 'Namespace', 'Statistic', 'Unit', 'Period'] specified as well\"", [k]),
	sprintf("Move %s into the MetricStat inside Metrics, or drop Metrics", [k]), _pf_asgttcx_url) if {
	some name in resources_of_type("AWS::AutoScaling::ScalingPolicy")
	_pf_aslib_arr(name, ["TargetTrackingConfiguration", "CustomizedMetricSpecification", "Metrics"])
	some k in _pf_asgttcx_simple
	not _pf_aslib_absent_at(name, ["TargetTrackingConfiguration", "CustomizedMetricSpecification", k])
}
