package cdk_preflight

import rego.v1

# リージョン -> Elastic Beanstalk エンドポイントの hosted zone ID
# （aws-cdk-lib の region-info から生成、2026-09-10 時点）
_pf_r53_ebz_table := {
	"af-south-1": "Z1EI3BVKMKK4AM",
	"ap-east-1": "ZPWYUBWRU171A",
	"ap-northeast-1": "Z1R25G3KIG2GBW",
	"ap-northeast-2": "Z3JE5OI70TWKCP",
	"ap-northeast-3": "ZNE5GEY1TIAGY",
	"ap-south-1": "Z18NTBI3Y7N9TZ",
	"ap-south-2": "Z10223522IBWPBF2C2FJS",
	"ap-southeast-1": "Z16FZ9L249IFLT",
	"ap-southeast-2": "Z2PCDNR3VC2G1N",
	"ap-southeast-3": "Z05913172VM7EAZB40TA8",
	"ap-southeast-4": "Z0666869LC74UHAO5YE4",
	"ap-southeast-5": "Z01812971H0QCYWSL7WOH",
	"ap-southeast-6": "Z01144401H1NECCLJDD4D",
	"ap-southeast-7": "Z1R25G3KIG2GBW",
	"ca-central-1": "ZJFCZL7SSZB5I",
	"ca-west-1": "Z1021028356Y0CYS11DQI",
	"eu-central-1": "Z1FRNW7UH4DEZJ",
	"eu-central-2": "Z00227012FSHBMZNNSJJI",
	"eu-north-1": "Z23GO28BZ5AETM",
	"eu-south-1": "Z10VDYYOA2JFKM",
	"eu-south-2": "Z23GO28BZ5AETM",
	"eu-west-1": "Z2NYPWQ7DFZAZH",
	"eu-west-2": "Z1GKAAAUGATPF1",
	"eu-west-3": "Z5WN6GAYWG5OB",
	"il-central-1": "Z02941091PERNCB1MI5H7",
	"me-south-1": "Z2BBTEKR2I36N2",
	"sa-east-1": "Z10X7K2B4QSOFV",
	"us-east-1": "Z117KPS5GTRQ2G",
	"us-east-2": "Z14LCN19Q5QHIC",
	"us-gov-east-1": "Z35TSARG0EJ4VU",
	"us-gov-west-1": "Z4KAURWC4UUUG",
	"us-west-1": "Z1LQECGX5PH1X",
	"us-west-2": "Z38NKT9BP95V3O",
}

violation contains make_diag_full("pf-route53-alias-beanstalk-zone-id", "ERROR", name,
	"Properties.AliasTarget.HostedZoneId",
	sprintf("The alias targets an Elastic Beanstalk environment in %s, whose hosted zone id is %s, but AliasTarget.HostedZoneId is '%s'", [reg, want, zid]),
	"Use the hosted zone id listed for that region's Elastic Beanstalk endpoint",
	"https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/resource-record-sets-values-alias.html") if {
	some name in resources_of_type("AWS::Route53::RecordSet")
	rs := _pf_r53lib_props(name)
	dns := _pf_r53lib_alias_dns(rs)
	endswith(dns, ".elasticbeanstalk.com")
	parts := split(trim_suffix(dns, ".elasticbeanstalk.com"), ".")
	reg := parts[count(parts) - 1]
	want := _pf_r53_ebz_table[reg]
	zid := _pf_r53lib_alias_zoneid(rs)
	zid != want
}

violation contains make_diag_full("pf-route53-alias-beanstalk-zone-id", "ERROR", name,
	sprintf("Properties.RecordSets[%d].AliasTarget.HostedZoneId", [_pf_it.index]),
	sprintf("The alias targets an Elastic Beanstalk environment in %s, whose hosted zone id is %s, but AliasTarget.HostedZoneId is '%s'", [reg, want, zid]),
	"Use the hosted zone id listed for that region's Elastic Beanstalk endpoint",
	"https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/resource-record-sets-values-alias.html") if {
	some name in resources_of_type("AWS::Route53::RecordSetGroup")
	some _pf_it in flatten_list(name, "Properties.RecordSets")
	rs := _pf_it.value
	is_object(rs)
	dns := _pf_r53lib_alias_dns(rs)
	endswith(dns, ".elasticbeanstalk.com")
	parts := split(trim_suffix(dns, ".elasticbeanstalk.com"), ".")
	reg := parts[count(parts) - 1]
	want := _pf_r53_ebz_table[reg]
	zid := _pf_r53lib_alias_zoneid(rs)
	zid != want
}
