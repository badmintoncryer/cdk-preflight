package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-kinesisanalytics-glue-database-region", "ERROR", name,
	"Properties.ApplicationConfiguration.ZeppelinApplicationConfiguration.CatalogConfiguration.GlueDataCatalogConfiguration.DatabaseARN",
	sprintf("the Glue database is in '%v' but the notebook deploys to '%v'; CreateApplication fails with \"Incorrect region in DatabaseArn, expecting '%v' but found '%v'.\"", [dr, region, region, dr]),
	"Point DatabaseARN at a Glue database in the application's own region",
	"https://docs.aws.amazon.com/managed-flink/latest/apiv2/API_GlueDataCatalogConfiguration.html") if {
	some name in resources_of_type("AWS::KinesisAnalyticsV2::Application")
	region := data.cdk_preflight.deploy_region
	is_string(region)
	dr := _pf_kinlib_arn_region(resolve(name, "Properties.ApplicationConfiguration.ZeppelinApplicationConfiguration.CatalogConfiguration.GlueDataCatalogConfiguration.DatabaseARN"), "glue")
	dr != region
}
