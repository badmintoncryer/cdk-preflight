package cdk_preflight

import rego.v1

# The registry schema types ExpirationInDays as a bare integer with no
# minimum, so 0 and negatives reach the service. Only the Expiration action
# was bench-verified; other day fields are left alone.
violation contains make_diag_full("pf-s3-lifecycle-expiration-positive", "ERROR", name,
	sprintf("Properties.LifecycleConfiguration.Rules.%d.ExpirationInDays", [r.index]),
	sprintf("ExpirationInDays is %v; S3 rejects the rule with \"'Days' for Expiration action must be a positive integer\"", [d]),
	"Use an ExpirationInDays of 1 or more",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-s3-bucket-rule.html") if {
	some name in resources_of_type("AWS::S3::Bucket")
	some r in flatten_list(name, "Properties.LifecycleConfiguration.Rules")
	is_object(r.value)
	raw := object.get(r.value, "ExpirationInDays", null)
	raw != null
	d := to_number(raw)
	d <= 0
}
