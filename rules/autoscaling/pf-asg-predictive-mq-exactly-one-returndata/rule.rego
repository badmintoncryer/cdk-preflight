package cdk_preflight

import rego.v1

_pf_asgprd_url := "https://docs.aws.amazon.com/autoscaling/ec2/APIReference/API_PutScalingPolicy.html"

_pf_asgprd_returning(qs) := count([1 |
	some q in qs
	is_object(q)
	object.get(q, "ReturnData", true) == true
])

violation contains make_diag_full("pf-asg-predictive-mq-exactly-one-returndata", "ERROR", name,
	sprintf("Properties.PredictiveScalingConfiguration.MetricSpecifications.%d.%s.MetricDataQueries", [i, k]),
	sprintf("%d of the metric data queries return data (ReturnData defaults to true); each customized metric must resolve to one time series and the policy create fails with \"Any expressions used must create exactly one time series\"", [n]),
	"Set ReturnData: false on every query but the final one", _pf_asgprd_url) if {
	some name in resources_of_type("AWS::AutoScaling::ScalingPolicy")
	some i, s in _pf_aslib_pmetrics(name)
	is_object(s)
	some k in ["CustomizedLoadMetricSpecification", "CustomizedScalingMetricSpecification"]
	spec := object.get(s, k, null)
	is_object(spec)
	qs := object.get(spec, "MetricDataQueries", null)
	is_array(qs)
	n := _pf_asgprd_returning(qs)
	n != 1
}
