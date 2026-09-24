package cdk_preflight

import rego.v1

# The five prefixes were measured one by one against CreateAccessEntry on
# 2026-09-25; the service names the offending prefix back. "sts:" is not
# reserved (it reached the cluster lookup), so the list is closed.
violation contains make_diag_full("pf-eks-accessentry-username-reserved-prefix", "ERROR", name,
	"Properties.Username",
	sprintf("Username %v starts with %v, which EKS reserves (\"The username must not begin with %v\")", [u, pfx, pfx]),
	"Leave Username out and let EKS derive it, or use a prefix of your own",
	"https://docs.aws.amazon.com/eks/latest/userguide/creating-access-entries.html") if {
	some name in resources_of_type("AWS::EKS::AccessEntry")
	u := resolve(name, "Properties.Username")
	_pf_ekslib_lit(u)
	some pfx in _pf_ekslib_reserved_prefixes
	startswith(u, pfx)
}
