package cdk_preflight

import rego.v1

_pf_s3mkk_fix := "Set EncryptionConfiguration.KmsKeyArn when SseAlgorithm is aws:kms"

_pf_s3mkk_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-s3-bucket-metadataconfiguration.html"

violation contains make_diag_full("pf-s3-metadata-kms-requires-key", "ERROR", name,
	sprintf("Properties.MetadataConfiguration.%v.EncryptionConfiguration.KmsKeyArn", [k]),
	"the metadata table asks for aws:kms encryption without a KmsKeyArn",
	_pf_s3mkk_fix, _pf_s3mkk_url) if {
	some name in resources_of_type("AWS::S3::Bucket")
	some k in ["JournalTableConfiguration", "InventoryTableConfiguration"]
	tc := resolve(name, sprintf("Properties.MetadataConfiguration.%v", [k]))
	is_object(tc)
	e := object.get(tc, "EncryptionConfiguration", {})
	is_object(e)
	object.get(e, "SseAlgorithm", "") == "aws:kms"
	object.get(e, "KmsKeyArn", "__pf_absent") == "__pf_absent"
}
