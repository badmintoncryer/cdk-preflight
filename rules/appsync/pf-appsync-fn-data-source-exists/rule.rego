package cdk_preflight

import rego.v1

# Judged only when the API is a sibling resource: every data source of an API
# created in this template has to be created here too.
_pf_fndatasourceexists_has(api, dsn) if {
	some d in resources_of_type("AWS::AppSync::DataSource")
	resolve(d, "Properties.ApiId") == api
	resolve(d, "Properties.Name") == dsn
}

violation contains make_diag_full("pf-appsync-fn-data-source-exists", "ERROR", name,
	"Properties.DataSourceName",
	sprintf("data source '%s' is never created on API '%s' in this template; the function create fails because the data source does not exist", [dsn, api]),
	"Add an AWS::AppSync::DataSource with that Name on the same API",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-appsync-functionconfiguration.html") if {
	some name in resources_of_type("AWS::AppSync::FunctionConfiguration")
	api := resolve(name, "Properties.ApiId")
	api in resources_of_type("AWS::AppSync::GraphQLApi")
	dsn := resolve(name, "Properties.DataSourceName")
	is_string(dsn)
	not _pf_fndatasourceexists_has(api, dsn)
}
