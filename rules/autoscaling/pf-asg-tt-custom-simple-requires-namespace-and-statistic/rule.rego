package cdk_preflight

import rego.v1

_pf_asgttcs_url := "https://docs.aws.amazon.com/autoscaling/ec2/APIReference/API_PutScalingPolicy.html"

_pf_asgttcs_required := ["Namespace", "Statistic"]

violation contains make_diag_full("pf-asg-tt-custom-simple-requires-namespace-and-statistic", "ERROR", name,
	sprintf("Properties.TargetTrackingConfiguration.CustomizedMetricSpecification.%s", [k]),
	sprintf("CustomizedMetricSpecification uses the single-metric form but has no %s; the policy create fails with \"Value null at 'targetTrackingConfiguration.customizedMetricSpecification.%s' failed to satisfy constraint: Member must not be null\"", [k, lower(k)]),
	sprintf("Set %s, or switch to the Metrics (metric math) form", [k]), _pf_asgttcs_url) if {
	some name in resources_of_type("AWS::AutoScaling::ScalingPolicy")
	_pf_aslib_obj(name, ["TargetTrackingConfiguration", "CustomizedMetricSpecification"])
	_pf_aslib_absent_at(name, ["TargetTrackingConfiguration", "CustomizedMetricSpecification", "Metrics"])
	some k in _pf_asgttcs_required
	_pf_aslib_absent_at(name, ["TargetTrackingConfiguration", "CustomizedMetricSpecification", k])
}
