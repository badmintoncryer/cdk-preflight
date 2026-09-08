package cdk_preflight

import rego.v1

_pf_cwwp_ok(p) if p in {1, 5, 10, 20, 30}

_pf_cwwp_ok(p) if {
	p > 0
	p % 60 == 0
}

violation contains make_diag_full("pf-cloudwatch-dashboard-widget-period", "ERROR", name,
	sprintf("Properties.DashboardBody (widgets[%d].properties.period)", [i]),
	sprintf("Widget %d sets period %v; PutDashboard fails with \"Should be multiple of 60\"", [i, p]),
	"Use 1, 5, 10, 20, 30 or a multiple of 60 seconds",
	"https://docs.aws.amazon.com/AmazonCloudWatch/latest/APIReference/CloudWatch-Dashboard-Body-Structure.html") if {
	some name in resources_of_type("AWS::CloudWatch::Dashboard")
	some i, w in _pf_cwlib_widgets(name)
	props := _pf_cwlib_wprops(w)
	p := object.get(props, "period", null)
	is_number(p)
	not _pf_cwwp_ok(p)
}
