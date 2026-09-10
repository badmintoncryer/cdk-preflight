package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-firehose-encryption-key-region", "ERROR", name,
	"Properties.DeliveryStreamEncryptionConfigurationInput.KeyARN",
	sprintf("the CMK is in %s but the stack deploys to %s; the stream create fails with \"Cross-region keys are not allowed for SSE. Please provide CMKs in the same region as firehose\"", [r, data.cdk_preflight.deploy_region]),
	"Use a CMK in the same region as the Firehose stream",
	"https://docs.aws.amazon.com/firehose/latest/APIReference/API_DeliveryStreamEncryptionConfigurationInput.html") if {
	some name in resources_of_type("AWS::KinesisFirehose::DeliveryStream")
	e := object.get(_pf_fhlib_props(name), "DeliveryStreamEncryptionConfigurationInput", null)
	is_object(e)
	arn := object.get(e, "KeyARN", null)
	_pf_fhlib_lit(arn)
	startswith(arn, "arn:")
	parts := split(arn, ":")
	count(parts) > 3
	r := parts[3]
	count(r) > 0
	r != data.cdk_preflight.deploy_region
}
