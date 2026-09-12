package cdk_preflight

import rego.v1

_pf_dsdeltasyncrequiresversioned_versioned(n) if resolve(n, "Properties.DynamoDBConfig.Versioned") == true

_pf_dsdeltasyncrequiresversioned_versioned(n) if resolve(n, "Properties.DynamoDBConfig.Versioned") == "true"

violation contains make_diag_full("pf-appsync-ds-delta-sync-requires-versioned", "ERROR", name,
	"Properties.DynamoDBConfig.DeltaSyncConfig",
	"DynamoDBConfig.DeltaSyncConfig is set but Versioned is not true; the data source create fails because delta sync is only available on a versioned data source",
	"Set DynamoDBConfig.Versioned: true, or drop DeltaSyncConfig",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-appsync-datasource.html") if {
	some name in resources_of_type("AWS::AppSync::DataSource")
	is_object(resolve(name, "Properties.DynamoDBConfig.DeltaSyncConfig"))
	not _pf_dsdeltasyncrequiresversioned_versioned(name)
}
