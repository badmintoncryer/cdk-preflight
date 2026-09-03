package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-cloudwatch-dashboard-widgets", "ERROR", name,
	"Properties.DashboardBody",
	"DashboardBody has no 'widgets' key; PutDashboard fails with \"Should have required property 'widgets'\"",
	"Add a widgets array to the dashboard body",
	"https://docs.aws.amazon.com/AmazonCloudWatch/latest/APIReference/CloudWatch-Dashboard-Body-Structure.html") if {
	some name in resources_of_type("AWS::CloudWatch::Dashboard")
	body := resolve(name, "Properties.DashboardBody")
	is_string(body)
	json.is_valid(body)
	obj := json.unmarshal(body)
	is_object(obj)
	object.get(obj, "widgets", "__pf_absent") == "__pf_absent"
}
