package cdk_preflight

import rego.v1

_pf_cf_field_level_encryption_requires_post_fix := "Allow POST/PUT on the behavior, or drop FieldLevelEncryptionId"

_pf_cf_field_level_encryption_requires_post_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cloudfront-distribution-cachebehavior.html"

violation contains make_diag_full("pf-cloudfront-field-level-encryption-requires-post", "ERROR", name, b.path,
	sprintf("FieldLevelEncryptionId is set but AllowedMethods %v has neither POST nor PUT", [am]),
	_pf_cf_field_level_encryption_requires_post_fix, _pf_cf_field_level_encryption_requires_post_url) if {
	some name in resources_of_type("AWS::CloudFront::Distribution")
	some b in _pf_cflib_behaviors(name)
	fle := object.get(b.value, "FieldLevelEncryptionId", "__pf_absent")
	fle != "__pf_absent"
	fle != ""
	am := object.get(b.value, "AllowedMethods", ["GET", "HEAD"])
	is_array(am)
	not "POST" in am
	not "PUT" in am
}
