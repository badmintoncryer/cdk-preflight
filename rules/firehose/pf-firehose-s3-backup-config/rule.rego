package cdk_preflight

import rego.v1

# Backup mode points deliveries at a second bucket that must be
# configured. Scoped to the benched ExtendedS3 destination. Absence is
# proven against the preprocessed document (see AGENTS.md).
_pf_fhsbc_outer(name) := c if {
	props := input.resources[name].properties
	is_object(props)
	c := object.get(props, "ExtendedS3DestinationConfiguration", {})
	is_object(c)
}

violation contains make_diag_full("pf-firehose-s3-backup-config", "ERROR", name,
	"Properties.ExtendedS3DestinationConfiguration.S3BackupConfiguration",
	"S3BackupMode is Enabled but S3BackupConfiguration is not set; the stream create fails with \"S3 backup destination configuration is required when enabling S3 backup.\"",
	"Add S3BackupConfiguration (bucket and role), or drop S3BackupMode",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-kinesisfirehose-deliverystream-extendeds3destinationconfiguration.html") if {
	some name in resources_of_type("AWS::KinesisFirehose::DeliveryStream")
	resolve(name, "Properties.ExtendedS3DestinationConfiguration.S3BackupMode") == "Enabled"
	x := _pf_fhsbc_outer(name)
	object.get(x, "S3BackupConfiguration", "__pf_absent") == "__pf_absent"
}
