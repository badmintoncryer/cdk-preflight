package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-cloudtrail-trail-kms-key-region", "ERROR", name,
	"Properties.KMSKeyId",
	sprintf("KMSKeyId is a single-Region KMS key in %v but the trail deploys to %v; CreateTrail rejects a key outside the trail's Region", [r, data.cdk_preflight.deploy_region]),
	"Reference a KMS key in the deployment Region, or a multi-Region key (mrk-)",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-cloudtrail-trail.html") if {
	some name in resources_of_type("AWS::CloudTrail::Trail")
	v := resolve(name, "Properties.KMSKeyId")
	_pf_ctlib_arn_of(v, "kms")
	not _pf_ctlib_multi_region_key(v)
	r := _pf_ctlib_region_mismatch(v)
}
