package cdk_preflight

import rego.v1

_pf_cf_origin_id_unique_fix := "Give each origin a distinct Id"

_pf_cf_origin_id_unique_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cloudfront-distribution-distributionconfig.html"

violation contains make_diag_full("pf-cloudfront-origin-id-unique", "ERROR", name, "Properties.DistributionConfig.Origins",
	sprintf("origin Id %v is used more than once", [k]),
	_pf_cf_origin_id_unique_fix, _pf_cf_origin_id_unique_url) if {
	some name in resources_of_type("AWS::CloudFront::Distribution")
	ids := [i | some o in _pf_cflib_origins(name); i := object.get(o.value, "Id", null); is_string(i)]
	some k in ids
	count([x | some x in ids; x == k]) > 1
}
