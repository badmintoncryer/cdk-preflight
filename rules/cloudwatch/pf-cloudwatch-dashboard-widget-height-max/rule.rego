package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-cloudwatch-dashboard-widget-height-max", "ERROR", name,
	sprintf("Properties.DashboardBody (widgets[%d].height)", [i]),
	sprintf("Widget %d has height=%v; PutDashboard fails with \"Should be <= 1000\"", [i, h]),
	"Keep widget height at 1000 or below",
	"https://docs.aws.amazon.com/AmazonCloudWatch/latest/APIReference/CloudWatch-Dashboard-Body-Structure.html") if {
	some name in resources_of_type("AWS::CloudWatch::Dashboard")
	some i, w in _pf_cwlib_widgets(name)
	is_object(w)
	h := object.get(w, "height", 0)
	is_number(h)
	h > 1000
}
