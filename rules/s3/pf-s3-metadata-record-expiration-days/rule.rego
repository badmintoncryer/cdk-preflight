package cdk_preflight

import rego.v1

_pf_s3mrd_fix := "Set RecordExpiration.Days to 7 or more"

_pf_s3mrd_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-s3-bucket-metadataconfiguration.html"

violation contains make_diag_full("pf-s3-metadata-record-expiration-days", "ERROR", name,
	"Properties.MetadataConfiguration.JournalTableConfiguration.RecordExpiration.Days",
	sprintf("RecordExpiration.Days is %v; S3 metadata journal tables keep records for at least 7 days", [d]),
	_pf_s3mrd_fix, _pf_s3mrd_url) if {
	some name in resources_of_type("AWS::S3::Bucket")
	re := resolve(name, "Properties.MetadataConfiguration.JournalTableConfiguration.RecordExpiration")
	is_object(re)
	object.get(re, "Expiration", "") == "ENABLED"
	raw := object.get(re, "Days", null)
	raw != null
	d := to_number(raw)
	d < 7
}
