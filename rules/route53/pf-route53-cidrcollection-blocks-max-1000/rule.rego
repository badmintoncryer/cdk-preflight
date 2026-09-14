package cdk_preflight

import rego.v1

# 1000 はロケーション 1 つ分（＝ ChangeCidrCollection 1 リクエスト分）の上限で、
# API の XML スキーマが持っているハードな境界。
# コレクション全体の 1000 は引き上げ可能なクォータ L-945D15E5 なので数えない（原則 6）。
violation contains make_diag_full("pf-route53-cidrcollection-blocks-max-1000", "ERROR", name,
	"Properties.Locations",
	sprintf("location %v lists %d CIDR blocks; CloudFormation sends one location per request and a request takes at most 1000", [li, n]),
	"Split the location's blocks across several locations or collections",
	"https://docs.aws.amazon.com/Route53/latest/APIReference/API_ChangeCidrCollection.html") if {
	some name in resources_of_type("AWS::Route53::CidrCollection")
	cs := _pf_r53z_cidrs(name)
	some li in {c[0] | some c in cs}
	n := count([c | some c in cs; c[0] == li])
	n > 1000
}
