package cdk_preflight

import rego.v1

_pf_cf_origin_group_failover_status_codes_fix := "Use 400, 403, 404, 405, 410, 414, 416, 500, 502, 503 or 504"

_pf_cf_origin_group_failover_status_codes_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cloudfront-distribution-distributionconfig.html"

violation contains make_diag_full("pf-cloudfront-origin-group-failover-status-codes", "ERROR", name, g.path,
	sprintf("%v is not a valid origin group failover status code", [n]),
	_pf_cf_origin_group_failover_status_codes_fix, _pf_cf_origin_group_failover_status_codes_url) if {
	some name in resources_of_type("AWS::CloudFront::Distribution")
	some g in _pf_cflib_origin_groups(name)
	fc := object.get(g.value, "FailoverCriteria", null)
	is_object(fc)
	sc := object.get(fc, "StatusCodes", null)
	is_object(sc)
	some c in object.get(sc, "Items", [])
	n := to_number(c)
	not n in {400, 403, 404, 405, 410, 414, 416, 500, 502, 503, 504}
}
