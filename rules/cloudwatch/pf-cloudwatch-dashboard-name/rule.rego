package cdk_preflight

import rego.v1

# Extra painful at deploy time: the invalid name also breaks the rollback
# DELETE, leaving the stack in ROLLBACK_FAILED (benched).
violation contains make_diag_full("pf-cloudwatch-dashboard-name", "ERROR", name,
	"Properties.DashboardName",
	sprintf("DashboardName '%s' contains invalid characters; PutDashboard allows only alphanumerics, dash (-) and underscore (_), and the failed stack cannot even roll back cleanly", [dn]),
	"Use only letters, digits, dash and underscore in the dashboard name",
	"https://docs.aws.amazon.com/AmazonCloudWatch/latest/APIReference/API_PutDashboard.html") if {
	some name in resources_of_type("AWS::CloudWatch::Dashboard")
	dn := resolve(name, "Properties.DashboardName")
	is_string(dn)
	not regex.match(`^[A-Za-z0-9_-]+$`, dn)
}
