package cdk_preflight

import rego.v1

# Judged only when the API is a sibling resource: every data source of an API
# created in this template has to be created here too.
_pf_nsintegrationdatasourceexists_has(api, dsn) if {
	some d in resources_of_type("AWS::AppSync::DataSource")
	resolve(d, "Properties.ApiId") == api
	resolve(d, "Properties.Name") == dsn
}

violation contains make_diag_full("pf-appsync-ns-integration-data-source-exists", "ERROR", name,
	"Properties.HandlerConfigs",
	sprintf("HandlerConfigs.%s.Integration names data source '%s', which this template never creates on API '%s'; the namespace create fails because the data source does not exist", [k, dsn, api]),
	"Add an AWS::AppSync::DataSource with that Name on the same API",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-appsync-channelnamespace.html") if {
	some name in resources_of_type("AWS::AppSync::ChannelNamespace")
	api := resolve(name, "Properties.ApiId")
	api in resources_of_type("AWS::AppSync::Api")
	hc := resolve(name, "Properties.HandlerConfigs")
	is_object(hc)
	some k, h in hc
	dsn := h.Integration.DataSourceName
	is_string(dsn)
	not _pf_nsintegrationdatasourceexists_has(api, dsn)
}
