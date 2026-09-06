package cdk_preflight

import rego.v1

# data.cdk_preflight.deploy_account is injected only when the app's account is
# concrete; the rule skips otherwise.
violation contains make_diag_full("pf-kinesisanalytics-service-role-account", "ERROR", name,
	"Properties.ServiceExecutionRole",
	sprintf("the role belongs to account %v but the application deploys into %v; CreateApplication fails with \"Cross-account pass role is not allowed, The role should belong to account '%v'\"", [ra, account, account]),
	"Create the service execution role in the application's own account",
	"https://docs.aws.amazon.com/managed-flink/latest/apiv2/API_CreateApplication.html") if {
	some name in resources_of_type("AWS::KinesisAnalyticsV2::Application")
	account := data.cdk_preflight.deploy_account
	is_string(account)
	ra := _pf_kinlib_arn_account(resolve(name, "Properties.ServiceExecutionRole"), "iam")
	ra != account
}
