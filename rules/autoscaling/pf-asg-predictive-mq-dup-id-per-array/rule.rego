package cdk_preflight

import rego.v1

_pf_asgpdi_url := "https://docs.aws.amazon.com/autoscaling/ec2/APIReference/API_PutScalingPolicy.html"

_pf_asgpdi_ids(qs) := [x |
	some q in qs
	is_object(q)
	x := object.get(q, "Id", null)
	is_string(x)
]

violation contains make_diag_full("pf-asg-predictive-mq-dup-id-per-array", "ERROR", name,
	sprintf("Properties.PredictiveScalingConfiguration.MetricSpecifications.%d.%s.MetricDataQueries", [i, k]),
	sprintf("%d of the %d metric data queries reuse an id already taken in the same array; CloudWatch rejects the duplicate and the policy create fails with \"The MetricDataQuery object ... has a problem or incorrect syntax\"", [dups, count(ids)]),
	"Give every MetricDataQuery in the array its own Id", _pf_asgpdi_url) if {
	some name in resources_of_type("AWS::AutoScaling::ScalingPolicy")
	some i, s in _pf_aslib_pmetrics(name)
	is_object(s)
	some k in _pf_aslib_pcustom
	spec := object.get(s, k, null)
	is_object(spec)
	qs := object.get(spec, "MetricDataQueries", null)
	is_array(qs)
	ids := _pf_asgpdi_ids(qs)
	uniq := count({x | some x in ids})
	dups := count(ids) - uniq
	dups > 0
}
