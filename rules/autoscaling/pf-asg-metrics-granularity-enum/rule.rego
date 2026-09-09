package cdk_preflight

import rego.v1

_pf_asgmge_url := "https://docs.aws.amazon.com/autoscaling/ec2/APIReference/API_CreateAutoScalingGroup.html"

violation contains make_diag_full("pf-asg-metrics-granularity-enum", "ERROR", name,
	sprintf("Properties.MetricsCollection.%d.Granularity", [i]),
	sprintf("Granularity '%s' is not offered; the only value Auto Scaling accepts is 1Minute and the group create fails with \"Valid metrics granularity type is: [1Minute]\"", [v]),
	"Use 1Minute", _pf_asgmge_url) if {
	some name in resources_of_type("AWS::AutoScaling::AutoScalingGroup")
	some i, m in _pf_aslib_arr(name, ["MetricsCollection"])
	is_object(m)
	v := object.get(m, "Granularity", null)
	_pf_aslib_lit(v)
	v != "1Minute"
}
