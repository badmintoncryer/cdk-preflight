package cdk_preflight

import rego.v1

# The engine knows this allowed-value list but reports it as W3030 (WARN),
# which never blocks a deploy; see AGENTS.md on the gray zone.
violation contains make_diag_full("pf-appsync-ds-rds-source-type-value", "ERROR", name,
	"Properties.RelationalDatabaseConfig.RelationalDatabaseSourceType",
	sprintf("RelationalDatabaseSourceType '%s' is not RDS_HTTP_ENDPOINT; the data source create rejects the value", [v]),
	"Use RDS_HTTP_ENDPOINT",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-appsync-datasource.html") if {
	some name in resources_of_type("AWS::AppSync::DataSource")
	v := resolve(name, "Properties.RelationalDatabaseConfig.RelationalDatabaseSourceType")
	is_string(v)
	not v in {"RDS_HTTP_ENDPOINT"}
}
