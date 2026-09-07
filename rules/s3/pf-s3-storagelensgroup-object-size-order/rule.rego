package cdk_preflight

import rego.v1

_pf_s3sgs_fix := "Set BytesGreaterThan below BytesLessThan"

_pf_s3sgs_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-s3-storagelensgroup-filter.html"

violation contains make_diag_full("pf-s3-storagelensgroup-object-size-order", "ERROR", name,
	"Properties.Filter.MatchObjectSize",
	sprintf("BytesGreaterThan (%v) is not smaller than BytesLessThan (%v); the group would match no object", [gt, lt]),
	_pf_s3sgs_fix, _pf_s3sgs_url) if {
	some name in resources_of_type("AWS::S3::StorageLensGroup")
	m := resolve(name, "Properties.Filter.MatchObjectSize")
	is_object(m)
	rawg := object.get(m, "BytesGreaterThan", null)
	rawg != null
	rawl := object.get(m, "BytesLessThan", null)
	rawl != null
	gt := to_number(rawg)
	lt := to_number(rawl)
	gt >= lt
}
