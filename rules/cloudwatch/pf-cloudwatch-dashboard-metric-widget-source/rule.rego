package cdk_preflight

import rego.v1

_pf_cwmws_source(props) if is_array(object.get(props, "metrics", null))

_pf_cwmws_source(props) if is_object(object.get(props, "annotations", null))

_pf_cwmws_ok(props) if {
	_pf_cwmws_source(props)
	is_string(object.get(props, "region", null))
}

violation contains make_diag_full("pf-cloudwatch-dashboard-metric-widget-source", "ERROR", name,
	sprintf("Properties.DashboardBody (widgets[%d].properties)", [i]),
	sprintf("Metric widget %d has no region plus data source; PutDashboard fails with \"The metric widget should have specified a region and a data source or an alarm annotation\"", [i]),
	"Give the widget a region and either a metrics array or an alarm annotation",
	"https://docs.aws.amazon.com/AmazonCloudWatch/latest/APIReference/CloudWatch-Dashboard-Body-Structure.html") if {
	some name in resources_of_type("AWS::CloudWatch::Dashboard")
	some i, w in _pf_cwlib_widgets(name)
	_pf_cwlib_wtype(w, "metric")
	props := _pf_cwlib_wprops(w)
	not _pf_cwmws_ok(props)
}
