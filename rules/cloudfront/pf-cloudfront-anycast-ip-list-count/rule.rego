package cdk_preflight

import rego.v1

_pf_cf_anycast_ip_list_count_fix := "Set IpCount to 21"

_pf_cf_anycast_ip_list_count_url := "https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/cloudfront-limits.html"

violation contains make_diag_full("pf-cloudfront-anycast-ip-list-count", "ERROR", name, "Properties.IpCount",
	sprintf("IpCount %v is not supported; CloudFront allocates exactly 21 anycast IPs", [c]),
	_pf_cf_anycast_ip_list_count_fix, _pf_cf_anycast_ip_list_count_url) if {
	some name in resources_of_type("AWS::CloudFront::AnycastIpList")
	raw := resolve(name, "Properties.IpCount")
	c := to_number(raw)
	c != 21
}
