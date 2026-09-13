package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-athena-dc-name-not-awsdatacatalog", "ERROR", name,
	"Properties.Name",
	"AwsDataCatalog is the built-in Glue catalog; CreateDataCatalog fails with \"DataCatalog name AwsDataCatalog is reserved.\"",
	"Drop the resource and reference AwsDataCatalog directly, or give the catalog another name",
	"https://docs.aws.amazon.com/athena/latest/APIReference/API_CreateDataCatalog.html") if {
	some name in resources_of_type("AWS::Athena::DataCatalog")
	resolve(name, "Properties.Name") == "AwsDataCatalog"
}
