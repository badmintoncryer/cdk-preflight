package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-logs-metric-dimension-selector", "ERROR", name,
	sprintf("Properties.MetricTransformations.%d.Dimensions", [i]),
	sprintf("Dimension '%s' has the literal value '%s'; PutMetricFilter fails with \"Invalid metric transformation: dimension value must be valid selector\"", [key, v]),
	"Point the dimension at a field from the log event ($.field for JSON, $1 for space-delimited)",
	"https://docs.aws.amazon.com/AmazonCloudWatch/latest/APIReference/API_PutMetricFilter.html") if {
	some name in resources_of_type("AWS::Logs::MetricFilter")
	some item in flatten_list(name, "Properties.MetricTransformations")
	i := item.index
	transform := item.value
	is_object(transform)
	dims := object.get(transform, "Dimensions", null)
	is_array(dims)
	some d in dims
	is_object(d)
	key := object.get(d, "Key", "")
	v := object.get(d, "Value", null)
	is_string(v)
	not startswith(v, "$")
}
