package cdk_preflight

import rego.v1

_pf_s3ndf_fix := "Keep at most one prefix and one suffix rule per filter; split the rest into separate configurations"

_pf_s3ndf_url := "https://docs.aws.amazon.com/AmazonS3/latest/userguide/notification-how-to-filtering.html"

violation contains make_diag_full("pf-s3-notification-duplicate-filter-type", "ERROR", name,
	sprintf("Properties.NotificationConfiguration.%v.%d.Filter.S3Key.Rules", [c.k, c.i]),
	sprintf("the filter declares '%v' twice; S3 accepts at most one prefix and one suffix rule per filter", [n]),
	_pf_s3ndf_fix, _pf_s3ndf_url) if {
	some name in resources_of_type("AWS::S3::Bucket")
	some c in _pf_s3lib_notifs(name)
	f := object.get(c.v, "Filter", {})
	is_object(f)
	key := object.get(f, "S3Key", {})
	is_object(key)
	rules := object.get(key, "Rules", [])
	is_array(rules)
	some i, j
	rules[i]
	rules[j]
	i < j
	is_object(rules[i])
	is_object(rules[j])
	n := lower(object.get(rules[i], "Name", ""))
	n != ""
	n == lower(object.get(rules[j], "Name", ""))
}
