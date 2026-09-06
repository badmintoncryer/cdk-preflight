package cdk_preflight

import rego.v1

_pf_s3sla_fix := "Enable the same metric under AccountLevel as well as under AccountLevel.BucketLevel"

_pf_s3sla_url := "https://docs.aws.amazon.com/AmazonS3/latest/userguide/storage_lens_basics_metrics_recommendations.html"

_pf_s3sla_account(name, m) if {
	al := resolve(name, sprintf("Properties.StorageLensConfiguration.AccountLevel.%v", [m]))
	is_object(al)
	object.get(al, "IsEnabled", false) == true
}

violation contains make_diag_full("pf-s3-storagelens-bucket-level-needs-account-level", "ERROR", name,
	sprintf("Properties.StorageLensConfiguration.AccountLevel.BucketLevel.%v", [m]),
	sprintf("%v is enabled for buckets but not at the account level; Storage Lens requires the account-level metric first", [m]),
	_pf_s3sla_fix, _pf_s3sla_url) if {
	some name in resources_of_type("AWS::S3::StorageLens")
	some m in ["AdvancedCostOptimizationMetrics", "AdvancedDataProtectionMetrics", "DetailedStatusCodesMetrics"]
	bl := resolve(name, sprintf("Properties.StorageLensConfiguration.AccountLevel.BucketLevel.%v", [m]))
	is_object(bl)
	object.get(bl, "IsEnabled", false) == true
	not _pf_s3sla_account(name, m)
}
