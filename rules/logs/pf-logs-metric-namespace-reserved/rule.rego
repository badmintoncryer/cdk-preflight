package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-logs-metric-namespace-reserved", "ERROR", name,
	sprintf("Properties.MetricTransformations.%d.MetricNamespace", [i]),
	sprintf("MetricNamespace '%s' is in the reserved AWS/ prefix; PutMetricFilter fails with \"Metric namespaces starting with AWS/ are reserved for AWS.\"", [ns]),
	"Publish into your own namespace",
	"https://docs.aws.amazon.com/AmazonCloudWatch/latest/APIReference/API_PutMetricFilter.html") if {
	some name in resources_of_type("AWS::Logs::MetricFilter")
	some item in flatten_list(name, "Properties.MetricTransformations")
	i := item.index
	transform := item.value
	is_object(transform)
	ns := object.get(transform, "MetricNamespace", null)
	is_string(ns)
	startswith(ns, "AWS/")
}
