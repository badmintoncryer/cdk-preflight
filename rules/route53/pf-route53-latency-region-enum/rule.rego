package cdk_preflight

import rego.v1

# 実在する AWS リージョン（aws-cdk-lib の region-info、2026-09-10 時点）。
# 新設リージョンが aws-cdk-lib に入るまでの間だけ取りこぼす。
violation contains make_diag_full("pf-route53-latency-region-enum", "ERROR", name,
	"Properties.Region",
	sprintf("'%s' is not an AWS Region; Route 53 rejects the record with \"Cannot find region\"", [r]),
	"Use the Region name the resource actually runs in (for example us-east-1)",
	"https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/routing-policy.html") if {
	some name in resources_of_type("AWS::Route53::RecordSet")
	rs := _pf_r53lib_props(name)
	r := _pf_r53lib_str(rs, "Region")
	not r in _pf_r53_regions
}

violation contains make_diag_full("pf-route53-latency-region-enum", "ERROR", name,
	sprintf("Properties.RecordSets[%d].Region", [_pf_it.index]),
	sprintf("'%s' is not an AWS Region; Route 53 rejects the record with \"Cannot find region\"", [r]),
	"Use the Region name the resource actually runs in (for example us-east-1)",
	"https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/routing-policy.html") if {
	some name in resources_of_type("AWS::Route53::RecordSetGroup")
	some _pf_it in flatten_list(name, "Properties.RecordSets")
	rs := _pf_it.value
	is_object(rs)
	r := _pf_r53lib_str(rs, "Region")
	not r in _pf_r53_regions
}
