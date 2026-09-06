package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-kinesis-resource-policy-region", "ERROR", name,
	"Properties.ResourceArn",
	sprintf("the target stream is in '%v' but the policy deploys to '%v'; PutResourcePolicy fails with \"The region specified in the ARN ... does not match the endpoint region\"", [ar, region]),
	"Attach the resource policy in the stream's own region",
	"https://docs.aws.amazon.com/kinesis/latest/APIReference/API_PutResourcePolicy.html") if {
	some name in resources_of_type("AWS::Kinesis::ResourcePolicy")
	region := data.cdk_preflight.deploy_region
	is_string(region)
	ar := _pf_kinlib_arn_region(resolve(name, "Properties.ResourceArn"), "kinesis")
	ar != region
}
