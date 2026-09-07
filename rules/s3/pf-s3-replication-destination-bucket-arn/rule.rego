package cdk_preflight

import rego.v1

_pf_s3rda_fix := "Write the destination as arn:aws:s3:::<bucket>"

_pf_s3rda_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-s3-bucket-replicationdestination.html"

violation contains make_diag_full("pf-s3-replication-destination-bucket-arn", "ERROR", name,
	sprintf("Properties.ReplicationConfiguration.Rules.%d.Destination.Bucket", [rule.index]),
	sprintf("Destination.Bucket is '%v'; S3 expects the destination bucket ARN, not its name", [b]),
	_pf_s3rda_fix, _pf_s3rda_url) if {
	some name in resources_of_type("AWS::S3::Bucket")
	some rule in flatten_list(name, "Properties.ReplicationConfiguration.Rules")
	is_object(rule.value)
	d := object.get(rule.value, "Destination", {})
	is_object(d)
	b := _pf_s3lib_lit(object.get(d, "Bucket", null))
	not startswith(b, "arn:")
}
