package cdk_preflight

import rego.v1

# Judged only when the data source is a sibling resource, so its Type is
# visible in this template.
_pf_resmaxbatchsizerequireslambdads_ds(api, dsn) := d if {
	some d in resources_of_type("AWS::AppSync::DataSource")
	resolve(d, "Properties.ApiId") == api
	resolve(d, "Properties.Name") == dsn
}

violation contains make_diag_full("pf-appsync-res-max-batch-size-requires-lambda-ds", "ERROR", name,
	"Properties.MaxBatchSize",
	sprintf("MaxBatchSize is set but data source '%s' is not AWS_LAMBDA; the resolver create fails because batching is only available on a direct Lambda resolver", [dsn]),
	"Point DataSourceName at an AWS_LAMBDA data source, or drop MaxBatchSize",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-appsync-resolver.html") if {
	some name in resources_of_type("AWS::AppSync::Resolver")
	to_number(resolve(name, "Properties.MaxBatchSize")) > 0
	api := resolve(name, "Properties.ApiId")
	dsn := resolve(name, "Properties.DataSourceName")
	d := _pf_resmaxbatchsizerequireslambdads_ds(api, dsn)
	resolve(d, "Properties.Type") != "AWS_LAMBDA"
}
