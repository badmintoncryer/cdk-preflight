package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-kinesis-consumer-stream-region", "ERROR", name,
	"Properties.StreamARN",
	sprintf("the stream is in '%v' but the consumer deploys to '%v'; RegisterStreamConsumer fails with \"The region specified in the ARN ... does not match the endpoint region\"", [sr, region]),
	"Register the consumer in the stream's own region",
	"https://docs.aws.amazon.com/kinesis/latest/APIReference/API_RegisterStreamConsumer.html") if {
	some name in resources_of_type("AWS::Kinesis::StreamConsumer")
	region := data.cdk_preflight.deploy_region
	is_string(region)
	sr := _pf_kinlib_arn_region(resolve(name, "Properties.StreamARN"), "kinesis")
	sr != region
}
