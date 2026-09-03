package cdk_preflight

import rego.v1

# Only key presence is checked: the service accepts arbitrary type values
# (bench dw04, type "metricc" deployed clean), so no enum validation.
_pf_cwdwf_widgets(name) := ws if {
	body := resolve(name, "Properties.DashboardBody")
	is_string(body)
	json.is_valid(body)
	obj := json.unmarshal(body)
	ws := object.get(obj, "widgets", [])
	is_array(ws)
}

violation contains make_diag_full("pf-cloudwatch-dashboard-widget-fields", "ERROR", name,
	sprintf("Properties.DashboardBody (widgets[%d])", [i]),
	sprintf("Dashboard widget %d is missing '%s'; PutDashboard fails with \"Should have required property '%s'\"", [i, key, key]),
	"Give every widget a type and a properties object",
	"https://docs.aws.amazon.com/AmazonCloudWatch/latest/APIReference/CloudWatch-Dashboard-Body-Structure.html") if {
	some name in resources_of_type("AWS::CloudWatch::Dashboard")
	some i, w in _pf_cwdwf_widgets(name)
	is_object(w)
	some key in {"type", "properties"}
	object.get(w, key, "__pf_absent") == "__pf_absent"
}
