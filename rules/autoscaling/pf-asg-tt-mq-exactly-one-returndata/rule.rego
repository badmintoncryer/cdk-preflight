package cdk_preflight

import rego.v1

_pf_asgttrd_url := "https://docs.aws.amazon.com/autoscaling/ec2/APIReference/API_PutScalingPolicy.html"

_pf_asgttrd_returning(name) := count([1 |
	some q in _pf_aslib_arr(name, ["TargetTrackingConfiguration", "CustomizedMetricSpecification", "Metrics"])
	is_object(q)
	object.get(q, "ReturnData", true) == true
])

violation contains make_diag_full("pf-asg-tt-mq-exactly-one-returndata", "ERROR", name,
	"Properties.TargetTrackingConfiguration.CustomizedMetricSpecification.Metrics",
	sprintf("%d of the metric data queries return data (ReturnData defaults to true); target tracking needs exactly one time series and the policy create fails with \"Exactly one element of the metrics list should return data\"", [n]),
	"Set ReturnData: false on every query but the one being tracked", _pf_asgttrd_url) if {
	some name in resources_of_type("AWS::AutoScaling::ScalingPolicy")
	_pf_aslib_arr(name, ["TargetTrackingConfiguration", "CustomizedMetricSpecification", "Metrics"])
	n := _pf_asgttrd_returning(name)
	n != 1
}
