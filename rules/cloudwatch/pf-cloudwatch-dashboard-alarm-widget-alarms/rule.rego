package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-cloudwatch-dashboard-alarm-widget-alarms", "ERROR", name,
	sprintf("Properties.DashboardBody (widgets[%d].properties.alarms)", [i]),
	sprintf("Alarm widget %d has no alarms list; PutDashboard fails with \"Should have required property 'alarms'\"", [i]),
	"List the alarm ARNs the widget should show",
	"https://docs.aws.amazon.com/AmazonCloudWatch/latest/APIReference/CloudWatch-Dashboard-Body-Structure.html") if {
	some name in resources_of_type("AWS::CloudWatch::Dashboard")
	some i, w in _pf_cwlib_widgets(name)
	_pf_cwlib_wtype(w, "alarm")
	props := _pf_cwlib_wprops(w)
	object.get(props, "alarms", "__pf_absent") == "__pf_absent"
}
