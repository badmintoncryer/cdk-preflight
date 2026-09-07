package cdk_preflight

import rego.v1

_pf_s3sga_fix := "Set DaysGreaterThan below DaysLessThan"

_pf_s3sga_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-s3-storagelensgroup-filter.html"

violation contains make_diag_full("pf-s3-storagelensgroup-object-age-order", "ERROR", name,
	"Properties.Filter.MatchObjectAge",
	sprintf("DaysGreaterThan (%v) is not smaller than DaysLessThan (%v); the group would match no object", [gt, lt]),
	_pf_s3sga_fix, _pf_s3sga_url) if {
	some name in resources_of_type("AWS::S3::StorageLensGroup")
	m := resolve(name, "Properties.Filter.MatchObjectAge")
	is_object(m)
	rawg := object.get(m, "DaysGreaterThan", null)
	rawg != null
	rawl := object.get(m, "DaysLessThan", null)
	rawl != null
	gt := to_number(rawg)
	lt := to_number(rawl)
	gt >= lt
}
