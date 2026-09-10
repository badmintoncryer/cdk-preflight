package cdk_preflight

import rego.v1

# S3 website エンドポイント -> そのリージョンの hosted zone ID
# （aws-cdk-lib の region-info から生成、2026-09-10 時点）
_pf_r53_s3wz_table := {
	"s3-website-ap-northeast-1.amazonaws.com": "Z2M4EHUR26P7ZW",
	"s3-website-ap-southeast-1.amazonaws.com": "Z3O0J2DXBE1FTB",
	"s3-website-ap-southeast-2.amazonaws.com": "Z1WCIGYICN2BYD",
	"s3-website-eu-west-1.amazonaws.com": "Z1BKCTXD74EZPE",
	"s3-website-sa-east-1.amazonaws.com": "Z7KQH4QJS55SO",
	"s3-website-us-east-1.amazonaws.com": "Z3AQBSTGFYJSTF",
	"s3-website-us-gov-west-1.amazonaws.com": "Z31GFT0UA1I2HV",
	"s3-website-us-west-1.amazonaws.com": "Z2F56UZL2M1ACD",
	"s3-website-us-west-2.amazonaws.com": "Z3BJ6K6RIION7M",
	"s3-website.af-south-1.amazonaws.com": "Z11KHD8FBVPUYU",
	"s3-website.ap-east-1.amazonaws.com": "ZNB98KWMFR0R6",
	"s3-website.ap-east-2.amazonaws.com": "Z064739330DAH7WJVOO93",
	"s3-website.ap-northeast-2.amazonaws.com": "Z3W03O7B5YMIYP",
	"s3-website.ap-northeast-3.amazonaws.com": "Z2YQB5RD63NC85",
	"s3-website.ap-south-1.amazonaws.com": "Z11RGJOFQNVJUP",
	"s3-website.ap-south-2.amazonaws.com": "Z02976202B4EZMXIPMXF7",
	"s3-website.ap-southeast-3.amazonaws.com": "Z01846753K324LI26A3VV",
	"s3-website.ap-southeast-4.amazonaws.com": "Z0312387243XT5FE14WFO",
	"s3-website.ap-southeast-5.amazonaws.com": "Z08660063OXLMA7F1FJHU",
	"s3-website.ap-southeast-7.amazonaws.com": "Z0031014GXUMRZG6I14G",
	"s3-website.ca-central-1.amazonaws.com": "Z1QDHH18159H29",
	"s3-website.ca-west-1.amazonaws.com": "Z03565811Z33SLEZTHOUL",
	"s3-website.cn-north-1.amazonaws.com.cn": "Z5CN8UMXT92WN",
	"s3-website.cn-northwest-1.amazonaws.com.cn": "Z282HJ1KT0DH03",
	"s3-website.eu-central-1.amazonaws.com": "Z21DNDUVLTQW6Q",
	"s3-website.eu-central-2.amazonaws.com": "Z030506016YDQGETNASS",
	"s3-website.eu-north-1.amazonaws.com": "Z3BAZG2TWCNX0D",
	"s3-website.eu-south-1.amazonaws.com": "Z3IXVV8C73GIO3",
	"s3-website.eu-south-2.amazonaws.com": "Z0081959F7139GRJC19J",
	"s3-website.eu-west-2.amazonaws.com": "Z3GKZC51ZF0DB4",
	"s3-website.eu-west-3.amazonaws.com": "Z3R1K369G5AVDG",
	"s3-website.il-central-1.amazonaws.com": "Z09640613K4A3MN55U7GU",
	"s3-website.me-central-1.amazonaws.com": "Z06143092I8HRXZRUZROF",
	"s3-website.me-south-1.amazonaws.com": "Z1MPMWCPA7YB62",
	"s3-website.us-east-2.amazonaws.com": "Z2O1EMRO9K5GLX",
	"s3-website.us-gov-east-1.amazonaws.com": "Z2NIFVYYW2VKV1",
	"s3-website.us-isof-east-1.csp.hci.ic.gov": "Z03373031FTGQH4MNG6ST",
	"s3-website.us-isof-south-1.csp.hci.ic.gov": "Z03376072I8GXC2DXUFXI",
}

violation contains make_diag_full("pf-route53-alias-s3-website-zone-id", "ERROR", name,
	"Properties.AliasTarget.HostedZoneId",
	sprintf("The alias targets the S3 website endpoint '%s', whose hosted zone id is %s, but AliasTarget.HostedZoneId is '%s'", [dns, want, zid]),
	"Use the hosted zone id listed for that region's S3 website endpoint (in the CDK, route53_targets.BucketWebsiteTarget does this)",
	"https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/resource-record-sets-values-alias.html") if {
	some name in resources_of_type("AWS::Route53::RecordSet")
	rs := _pf_r53lib_props(name)
	dns := _pf_r53lib_alias_dns(rs)
	want := _pf_r53_s3wz_table[dns]
	zid := _pf_r53lib_alias_zoneid(rs)
	zid != want
}

violation contains make_diag_full("pf-route53-alias-s3-website-zone-id", "ERROR", name,
	sprintf("Properties.RecordSets[%d].AliasTarget.HostedZoneId", [_pf_it.index]),
	sprintf("The alias targets the S3 website endpoint '%s', whose hosted zone id is %s, but AliasTarget.HostedZoneId is '%s'", [dns, want, zid]),
	"Use the hosted zone id listed for that region's S3 website endpoint (in the CDK, route53_targets.BucketWebsiteTarget does this)",
	"https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/resource-record-sets-values-alias.html") if {
	some name in resources_of_type("AWS::Route53::RecordSetGroup")
	some _pf_it in flatten_list(name, "Properties.RecordSets")
	rs := _pf_it.value
	is_object(rs)
	dns := _pf_r53lib_alias_dns(rs)
	want := _pf_r53_s3wz_table[dns]
	zid := _pf_r53lib_alias_zoneid(rs)
	zid != want
}
