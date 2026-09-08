package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-cloudwatch-dashboard-widget-stat-syntax", "ERROR", name,
	sprintf("Properties.DashboardBody (widgets[%d].properties.stat)", [i]),
	sprintf("Widget %d has stat '%s'; PutDashboard fails with \"Should match pattern\" for the statistic grammar", [i, st]),
	"Use SampleCount, Average, Sum, Minimum, Maximum, IQM, a percentile (p90) or a trimmed statistic (TM90)",
	"https://docs.aws.amazon.com/AmazonCloudWatch/latest/APIReference/CloudWatch-Dashboard-Body-Structure.html") if {
	some name in resources_of_type("AWS::CloudWatch::Dashboard")
	some i, w in _pf_cwlib_widgets(name)
	props := _pf_cwlib_wprops(w)
	st := object.get(props, "stat", null)
	is_string(st)
	not _pf_cwlib_stat_ok(st)
}
