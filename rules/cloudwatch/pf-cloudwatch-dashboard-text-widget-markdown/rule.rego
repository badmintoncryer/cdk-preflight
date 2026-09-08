package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-cloudwatch-dashboard-text-widget-markdown", "ERROR", name,
	sprintf("Properties.DashboardBody (widgets[%d].properties.markdown)", [i]),
	sprintf("Text widget %d has no markdown; PutDashboard fails with \"Should have required property 'markdown'\"", [i]),
	"Give the text widget a markdown string",
	"https://docs.aws.amazon.com/AmazonCloudWatch/latest/APIReference/CloudWatch-Dashboard-Body-Structure.html") if {
	some name in resources_of_type("AWS::CloudWatch::Dashboard")
	some i, w in _pf_cwlib_widgets(name)
	_pf_cwlib_wtype(w, "text")
	props := _pf_cwlib_wprops(w)
	object.get(props, "markdown", "__pf_absent") == "__pf_absent"
}
