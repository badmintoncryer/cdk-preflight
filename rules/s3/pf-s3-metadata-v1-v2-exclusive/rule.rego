package cdk_preflight

import rego.v1

_pf_s3mdx_fix := "Keep MetadataConfiguration (V2) and drop the older MetadataTableConfiguration"

_pf_s3mdx_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-s3-bucket-metadataconfiguration.html"

violation contains make_diag_full("pf-s3-metadata-v1-v2-exclusive", "ERROR", name, "Properties.MetadataTableConfiguration",
	"the bucket sets both MetadataConfiguration and the older MetadataTableConfiguration; S3 accepts one metadata configuration per bucket",
	_pf_s3mdx_fix, _pf_s3mdx_url) if {
	some name in resources_of_type("AWS::S3::Bucket")
	props := input.resources[name].properties
	is_object(props)
	object.get(props, "MetadataConfiguration", "__pf_absent") != "__pf_absent"
	object.get(props, "MetadataTableConfiguration", "__pf_absent") != "__pf_absent"
}
