package cdk_preflight

import rego.v1

_pf_cwpm_keys := {"x", "y"}

violation contains make_diag_full("pf-cloudwatch-dashboard-widget-position-min", "ERROR", name,
	sprintf("Properties.DashboardBody (widgets[%d].%s)", [i, key]),
	sprintf("Widget %d has %s=%v; PutDashboard fails with \"Should be >= 0\"", [i, key, v]),
	"Keep widget x and y at 0 or above",
	"https://docs.aws.amazon.com/AmazonCloudWatch/latest/APIReference/CloudWatch-Dashboard-Body-Structure.html") if {
	some name in resources_of_type("AWS::CloudWatch::Dashboard")
	some i, w in _pf_cwlib_widgets(name)
	is_object(w)
	some key in _pf_cwpm_keys
	v := object.get(w, key, 0)
	is_number(v)
	v < 0
}
