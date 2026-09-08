package cdk_preflight

import rego.v1

_pf_cwyx_sides := {"left", "right"}

violation contains make_diag_full("pf-cloudwatch-dashboard-yaxis-range", "ERROR", name,
	sprintf("Properties.DashboardBody (widgets[%d].properties.yAxis.%s)", [i, side]),
	sprintf("Widget %d has yAxis %s min=%v and max=%v; PutDashboard rejects the pair with \"Should be <= %v\"", [i, side, mn, mx, mx]),
	"Set the axis min below its max",
	"https://docs.aws.amazon.com/AmazonCloudWatch/latest/APIReference/CloudWatch-Dashboard-Body-Structure.html") if {
	some name in resources_of_type("AWS::CloudWatch::Dashboard")
	some i, w in _pf_cwlib_widgets(name)
	props := _pf_cwlib_wprops(w)
	axis := object.get(props, "yAxis", null)
	is_object(axis)
	some side in _pf_cwyx_sides
	spec := object.get(axis, side, null)
	is_object(spec)
	mn := object.get(spec, "min", null)
	mx := object.get(spec, "max", null)
	is_number(mn)
	is_number(mx)
	mn >= mx
}
