package cdk_preflight

import rego.v1

_pf_dshttpendpointscheme_ok(e) if startswith(e, "http://")

_pf_dshttpendpointscheme_ok(e) if startswith(e, "https://")

violation contains make_diag_full("pf-appsync-ds-http-endpoint-scheme", "ERROR", name,
	"Properties.HttpConfig.Endpoint",
	sprintf("HttpConfig.Endpoint '%s' is not an http or https URL; the data source create rejects the endpoint", [e]),
	"Use a full http:// or https:// endpoint",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-appsync-datasource.html") if {
	some name in resources_of_type("AWS::AppSync::DataSource")
	e := resolve(name, "Properties.HttpConfig.Endpoint")
	is_string(e)
	not _pf_dshttpendpointscheme_ok(e)
}
