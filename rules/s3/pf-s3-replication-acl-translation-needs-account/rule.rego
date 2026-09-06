package cdk_preflight

import rego.v1

_pf_s3rat_fix := "Set Destination.Account to the destination bucket owner account id"

_pf_s3rat_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-s3-bucket-replicationdestination.html"

violation contains make_diag_full("pf-s3-replication-acl-translation-needs-account", "ERROR", name,
	sprintf("Properties.ReplicationConfiguration.Rules.%d.Destination.AccessControlTranslation", [rule.index]),
	"AccessControlTranslation is set but Destination.Account is missing; S3 needs the expected destination bucket owner",
	_pf_s3rat_fix, _pf_s3rat_url) if {
	some name in resources_of_type("AWS::S3::Bucket")
	some rule in flatten_list(name, "Properties.ReplicationConfiguration.Rules")
	is_object(rule.value)
	d := object.get(rule.value, "Destination", {})
	is_object(d)
	object.get(d, "AccessControlTranslation", "__pf_absent") != "__pf_absent"
	object.get(d, "Account", "__pf_absent") == "__pf_absent"
}
