package cdk_preflight

import rego.v1

# DefaultValue is emitted when a log line does not match, but a dimension
# value can only come from a match — the service rejects the combination.
violation contains make_diag_full("pf-logs-metric-dimensions-default-exclusive", "ERROR", name,
	sprintf("Properties.MetricTransformations.%d.DefaultValue", [t.index]),
	"The metric transformation sets both Dimensions and DefaultValue; the service rejects it with \"Invalid metric transformation: dimensions and default value are mutually exclusive properties\"",
	"Drop DefaultValue when the transformation has Dimensions, or drop the Dimensions",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-logs-metricfilter-metrictransformation.html") if {
	some name in resources_of_type("AWS::Logs::MetricFilter")
	some t in flatten_list(name, "Properties.MetricTransformations")
	is_object(t.value)
	object.get(t.value, "DefaultValue", "__pf_absent") != "__pf_absent"
	dims := object.get(t.value, "Dimensions", null)
	is_array(dims)
	count(dims) > 0
}
