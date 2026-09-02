package cdk_preflight

import rego.v1

# Every CloudFront distribution is aliased through the single global hosted
# zone Z2FDTNDATAQYW2. Any other AliasTarget.HostedZoneId (an ALB's regional
# zone id is the classic paste error) fails at deploy time with "the alias
# target name does not lie within the target zone".
violation contains make_diag_full("pf-route53-alias-cloudfront-zone-id", "ERROR", name,
	"Properties.AliasTarget.HostedZoneId",
	sprintf("The alias targets a CloudFront domain, so AliasTarget.HostedZoneId must be Z2FDTNDATAQYW2, not '%s'", [zid]),
	"Set AliasTarget.HostedZoneId to Z2FDTNDATAQYW2 (in the CDK, route53_targets.CloudFrontTarget does this)",
	"https://docs.aws.amazon.com/general/latest/gr/cf_region.html") if {
	some name in resources_of_type("AWS::Route53::RecordSet")
	dns := resolve(name, "Properties.AliasTarget.DNSName")
	is_string(dns)
	endswith(trim_suffix(lower(dns), "."), ".cloudfront.net")
	zid := resolve(name, "Properties.AliasTarget.HostedZoneId")
	is_string(zid)
	zid != "Z2FDTNDATAQYW2"
}
