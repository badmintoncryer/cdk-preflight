package cdk_preflight

import rego.v1

_pf_s3sle_fix := "List buckets or regions in the scope filter, or drop the filter entirely"

_pf_s3sle_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-s3-storagelens-storagelensconfiguration.html"

_pf_s3sle_entries(sel) := [x |
	some f in ["Buckets", "Regions"]
	l := object.get(sel, f, [])
	is_array(l)
	some x in l
]

violation contains make_diag_full("pf-s3-storagelens-include-empty", "ERROR", name,
	sprintf("Properties.StorageLensConfiguration.%v", [k]),
	sprintf("%v lists neither a bucket nor a region; Storage Lens rejects an empty scope filter", [k]),
	_pf_s3sle_fix, _pf_s3sle_url) if {
	some name in resources_of_type("AWS::S3::StorageLens")
	some k in ["Include", "Exclude"]
	sel := resolve(name, sprintf("Properties.StorageLensConfiguration.%v", [k]))
	is_object(sel)
	count(_pf_s3sle_entries(sel)) == 0
}
