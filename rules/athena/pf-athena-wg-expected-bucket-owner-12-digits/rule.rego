package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-athena-wg-expected-bucket-owner-12-digits", "ERROR", name,
	"Properties.WorkGroupConfiguration.ResultConfiguration.ExpectedBucketOwner",
	sprintf("ExpectedBucketOwner '%v' is %d characters, short of a 12-digit account id; CreateWorkGroup fails with \"Value at 'configuration.resultConfiguration.expectedBucketOwner' failed to satisfy constraint: Member must have length greater than or equal to 12\"", [owner, count(owner)]),
	"Use the 12-digit AWS account ID that owns the result bucket",
	"https://docs.aws.amazon.com/athena/latest/APIReference/API_ResultConfiguration.html") if {
	some name in resources_of_type("AWS::Athena::WorkGroup")
	owner := resolve(name, "Properties.WorkGroupConfiguration.ResultConfiguration.ExpectedBucketOwner")
	_pf_athlib_lit(owner)
	count(owner) < 12
}
