package cdk_preflight

import rego.v1

# data.cdk_preflight.deploy_region is injected only in enforce mode with a
# concrete region; the rule skips otherwise.
violation contains make_diag_full("pf-kinesis-encryption-key-region", "ERROR", name,
	"Properties.StreamEncryption.KeyId",
	sprintf("the KMS key is in '%v' but the stream deploys to '%v'; the stack fails with \"KMSNotFoundException: Invalid arn %v\"", [kr, region, kr]),
	"Point StreamEncryption.KeyId at a key in the stream's own region (or use the alias alias/aws/kinesis)",
	"https://docs.aws.amazon.com/kinesis/latest/APIReference/API_StartStreamEncryption.html") if {
	some name in resources_of_type("AWS::Kinesis::Stream")
	region := data.cdk_preflight.deploy_region
	is_string(region)
	kr := _pf_kinlib_arn_region(resolve(name, "Properties.StreamEncryption.KeyId"), "kms")
	kr != region
}
