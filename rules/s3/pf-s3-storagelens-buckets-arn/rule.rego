package cdk_preflight

import rego.v1

_pf_s3slb_fix := "Write each scope bucket as arn:aws:s3:::<bucket>"

_pf_s3slb_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-s3-storagelens-storagelensconfiguration.html"

violation contains make_diag_full("pf-s3-storagelens-buckets-arn", "ERROR", name,
	sprintf("Properties.StorageLensConfiguration.%v.Buckets.%d", [k, c.index]),
	sprintf("'%v' is a bucket name; the Storage Lens scope takes bucket ARNs", [b]),
	_pf_s3slb_fix, _pf_s3slb_url) if {
	some name in resources_of_type("AWS::S3::StorageLens")
	some k in ["Include", "Exclude"]
	some c in flatten_list(name, sprintf("Properties.StorageLensConfiguration.%v.Buckets", [k]))
	b := _pf_s3lib_lit(c.value)
	not startswith(b, "arn:")
}
