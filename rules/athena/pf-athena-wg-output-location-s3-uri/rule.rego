package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-athena-wg-output-location-s3-uri", "ERROR", name,
	"Properties.WorkGroupConfiguration.ResultConfiguration.OutputLocation",
	sprintf("OutputLocation '%v' is not an S3 URI; CreateWorkGroup fails with \"OutputLocation is not a valid S3 path.\"", [loc]),
	"Write the result location as s3://<bucket>/<prefix>/",
	"https://docs.aws.amazon.com/athena/latest/APIReference/API_ResultConfiguration.html") if {
	some name in resources_of_type("AWS::Athena::WorkGroup")
	loc := resolve(name, "Properties.WorkGroupConfiguration.ResultConfiguration.OutputLocation")
	_pf_athlib_lit(loc)
	not startswith(loc, "s3://")
}
