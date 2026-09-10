package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-firehose-bucket-arn-format", "ERROR", name,
	sprintf("%s.BucketARN", [path]),
	sprintf("BucketARN '%s' is not an S3 bucket ARN; the stream create fails with \"failed to satisfy constraint: Member must satisfy regular expression pattern: arn:.*:s3:::[\\w\\.\\-]{1,255}\"", [arn]),
	"Write the ARN as arn:aws:s3:::bucket-name (no region, no account)",
	"https://docs.aws.amazon.com/firehose/latest/APIReference/API_ExtendedS3DestinationConfiguration.html") if {
	some [name, path, c] in _pf_fhlib_prefixed
	arn := object.get(c, "BucketARN", null)
	_pf_fhlib_lit(arn)
	startswith(arn, "arn:")
	not regex.match(`^arn:[^:]*:s3:::[A-Za-z0-9._-]{1,255}$`, arn)
}
