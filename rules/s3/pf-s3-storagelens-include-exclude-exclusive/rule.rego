package cdk_preflight

import rego.v1

_pf_s3slx_fix := "Keep one of Include / Exclude in the Storage Lens configuration"

_pf_s3slx_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-s3-storagelens-storagelensconfiguration.html"

violation contains make_diag_full("pf-s3-storagelens-include-exclude-exclusive", "ERROR", name,
	"Properties.StorageLensConfiguration.Exclude",
	"the configuration sets both Include and Exclude; Storage Lens accepts only one scope filter",
	_pf_s3slx_fix, _pf_s3slx_url) if {
	some name in resources_of_type("AWS::S3::StorageLens")
	cfg := resolve(name, "Properties.StorageLensConfiguration")
	is_object(cfg)
	object.get(cfg, "Include", "__pf_absent") != "__pf_absent"
	object.get(cfg, "Exclude", "__pf_absent") != "__pf_absent"
}
