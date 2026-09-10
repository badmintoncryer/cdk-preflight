package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-firehose-iceberg-backup-mode", "ERROR", name,
	"Properties.IcebergDestinationConfiguration.s3BackupMode",
	sprintf("s3BackupMode is '%s'; the stream create fails with \"S3BackupMode.%s is not supported for Iceberg as destination.\"", [m, m]),
	"Use FailedDataOnly for an Iceberg destination",
	"https://docs.aws.amazon.com/firehose/latest/APIReference/API_IcebergDestinationConfiguration.html") if {
	some [name, path, c] in _pf_fhlib_dests
	path == "Properties.IcebergDestinationConfiguration"
	m := object.get(c, "s3BackupMode", null)
	_pf_fhlib_lit(m)
	m != "FailedDataOnly"
}
