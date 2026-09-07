package cdk_preflight

import rego.v1

_pf_s3itd_fix := "Set the ARCHIVE_ACCESS Days below the DEEP_ARCHIVE_ACCESS Days"

_pf_s3itd_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-s3-bucket-intelligenttieringconfiguration.html"

violation contains make_diag_full("pf-s3-intelligent-tiering-archive-before-deep", "ERROR", name,
	sprintf("Properties.IntelligentTieringConfigurations.%d.Tierings", [c.index]),
	sprintf("ARCHIVE_ACCESS is set to %v days but DEEP_ARCHIVE_ACCESS to %v; the archive tier must come first", [a, d]),
	_pf_s3itd_fix, _pf_s3itd_url) if {
	some name in resources_of_type("AWS::S3::Bucket")
	some c in flatten_list(name, "Properties.IntelligentTieringConfigurations")
	is_object(c.value)
	tiers := object.get(c.value, "Tierings", [])
	is_array(tiers)
	some t1 in tiers
	some t2 in tiers
	is_object(t1)
	is_object(t2)
	object.get(t1, "AccessTier", "") == "ARCHIVE_ACCESS"
	object.get(t2, "AccessTier", "") == "DEEP_ARCHIVE_ACCESS"
	rawa := object.get(t1, "Days", null)
	rawa != null
	rawd := object.get(t2, "Days", null)
	rawd != null
	a := to_number(rawa)
	d := to_number(rawd)
	a >= d
}
