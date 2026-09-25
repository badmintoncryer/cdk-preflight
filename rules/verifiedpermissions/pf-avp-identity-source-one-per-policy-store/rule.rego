package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-avp-identity-source-one-per-policy-store", "ERROR", name, "Properties.PolicyStoreId",
	sprintf("%v identity sources point at policy store %v; a policy store takes one (quota 1, not adjustable) and the extra CreateIdentitySource answers \"Identity Source Limit Exceeded.\"", [count(peers), store]),
	"Keep one IdentitySource per policy store; give the second provider its own policy store",
	"https://docs.aws.amazon.com/verifiedpermissions/latest/userguide/quotas.html") if {
	some name in resources_of_type("AWS::VerifiedPermissions::IdentitySource")
	store := resolve(name, "Properties.PolicyStoreId")
	is_string(store)
	peers := {n |
		some n in resources_of_type("AWS::VerifiedPermissions::IdentitySource")
		resolve(n, "Properties.PolicyStoreId") == store
	}
	count(peers) > 1
}
