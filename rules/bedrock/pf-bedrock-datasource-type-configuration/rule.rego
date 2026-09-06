package cdk_preflight

import rego.v1

# The schema requires only Type; CreateDataSource requires the connector block
# named after it ("s3Configuration is required when data source type is S3",
# measured 2026-09-06).
_pf_dstc_member := {"S3": "S3Configuration", "WEB": "WebConfiguration", "CONFLUENCE": "ConfluenceConfiguration", "SALESFORCE": "SalesforceConfiguration", "SHAREPOINT": "SharePointConfiguration"}

violation contains make_diag_full("pf-bedrock-datasource-type-configuration", "ERROR", name,
	sprintf("Properties.DataSourceConfiguration.%s", [m]),
	sprintf("DataSourceConfiguration.Type is %s but %s is missing; CreateDataSource fails with \"%s%s is required when data source type is %s\"", [t, m, lower(substring(m, 0, 1)), substring(m, 1, -1), t]),
	sprintf("Add DataSourceConfiguration.%s, or change Type", [m]),
	"https://docs.aws.amazon.com/bedrock/latest/APIReference/API_agent_CreateDataSource.html") if {
	some name in resources_of_type("AWS::Bedrock::DataSource")
	cfg := object.get(_pf_bedrocklib_props(name), "DataSourceConfiguration", null)
	is_object(cfg)
	t := cfg.Type
	m := _pf_dstc_member[t]
	not _pf_bedrocklib_has(cfg, m)
}
