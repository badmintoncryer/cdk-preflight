package cdk_preflight

import rego.v1

# Only the two benched maxima are claimed (x <= 23, width <= 24).
_pf_cwdwp_widgets(name) := ws if {
	body := resolve(name, "Properties.DashboardBody")
	is_string(body)
	json.is_valid(body)
	obj := json.unmarshal(body)
	ws := object.get(obj, "widgets", [])
	is_array(ws)
}

_pf_cwdwp_max := {"x": 23, "width": 24}

violation contains make_diag_full("pf-cloudwatch-dashboard-widget-position", "ERROR", name,
	sprintf("Properties.DashboardBody (widgets[%d].%s)", [i, key]),
	sprintf("Dashboard widget %d has %s=%v, above the maximum %v; PutDashboard fails with \"Should be <= %v\"", [i, key, v, m, m]),
	"Keep x within 0-23 and width within 1-24 (24-column grid)",
	"https://docs.aws.amazon.com/AmazonCloudWatch/latest/APIReference/CloudWatch-Dashboard-Body-Structure.html") if {
	some name in resources_of_type("AWS::CloudWatch::Dashboard")
	some i, w in _pf_cwdwp_widgets(name)
	is_object(w)
	some key, m in _pf_cwdwp_max
	v := object.get(w, key, 0)
	is_number(v)
	v > m
}
