package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-cloudwatch-dashboard-body-json", "ERROR", name,
	"Properties.DashboardBody",
	"DashboardBody does not parse as JSON; PutDashboard fails with \"The field DashboardBody must be a valid JSON object\"",
	"Fix the JSON syntax of the dashboard body",
	"https://docs.aws.amazon.com/AmazonCloudWatch/latest/APIReference/CloudWatch-Dashboard-Body-Structure.html") if {
	some name in resources_of_type("AWS::CloudWatch::Dashboard")
	body := resolve(name, "Properties.DashboardBody")
	is_string(body)
	not json.is_valid(body)
}
