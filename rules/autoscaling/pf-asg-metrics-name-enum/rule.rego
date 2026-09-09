package cdk_preflight

import rego.v1

_pf_asgmne_url := "https://docs.aws.amazon.com/autoscaling/ec2/APIReference/API_CreateAutoScalingGroup.html"

_pf_asgmne_ok := {
	"GroupMinSize", "GroupMaxSize", "GroupDesiredCapacity", "GroupInServiceInstances",
	"GroupPendingInstances", "GroupStandbyInstances", "GroupTerminatingInstances", "GroupTotalInstances",
	"GroupInServiceCapacity", "GroupPendingCapacity", "GroupStandbyCapacity", "GroupTerminatingCapacity",
	"GroupTotalCapacity", "WarmPoolDesiredCapacity", "WarmPoolWarmedCapacity", "WarmPoolPendingCapacity",
	"WarmPoolTerminatingCapacity", "WarmPoolTotalCapacity", "GroupAndWarmPoolDesiredCapacity",
	"GroupAndWarmPoolTotalCapacity",
}

violation contains make_diag_full("pf-asg-metrics-name-enum", "ERROR", name,
	sprintf("Properties.MetricsCollection.%d.Metrics.%d", [i, j]),
	sprintf("'%s' is not a group metric; the group create fails with \"Valid metrics collection types are: [GroupMinSize, GroupMaxSize, ...]\"", [v]),
	"Use a metric name from the Auto Scaling group metrics list", _pf_asgmne_url) if {
	some name in resources_of_type("AWS::AutoScaling::AutoScalingGroup")
	some i, m in _pf_aslib_arr(name, ["MetricsCollection"])
	is_object(m)
	ms := object.get(m, "Metrics", null)
	is_array(ms)
	some j, v in ms
	_pf_aslib_lit(v)
	not v in _pf_asgmne_ok
}
