package cdk_preflight

import rego.v1

# Every version the catalogue publishes has this shape (1677 in us-east-1 and
# 1346 in ap-northeast-1, read 2026-09-25 with describe-addon-versions), so a
# string of another shape can only come back as "not supported". A version of
# the right shape that does not exist is left alone - that needs the catalogue.
violation contains make_diag_full("pf-eks-addon-version-format", "ERROR", name,
	"Properties.AddonVersion",
	sprintf("AddonVersion %v is not of the form vX.Y.Z-eksbuild.N (\"Addon version specified is not supported\")", [v]),
	"Use a published version, e.g. v1.23.1-eksbuild.1 (aws eks describe-addon-versions)",
	"https://docs.aws.amazon.com/eks/latest/APIReference/API_CreateAddon.html") if {
	some name in resources_of_type("AWS::EKS::Addon")
	v := resolve(name, "Properties.AddonVersion")
	_pf_ekslib_lit(v)
	not regex.match(`^v[0-9]+\.[0-9]+\.[0-9]+-eksbuild\.[0-9A-Za-z]+$`, v)
}
