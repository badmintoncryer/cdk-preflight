package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-iam-oidc-provider-client-id-count", "ERROR", name,
	"Properties.ClientIdList",
	sprintf("OIDC provider lists %d client ids; IAM caps ClientIdsPerOpenIdConnectProvider at 100 and rejects the provider with LimitExceeded", [n]),
	"Register at most 100 audiences per provider; split the rest across additional providers or drop the unused ones",
	"https://docs.aws.amazon.com/IAM/latest/APIReference/API_CreateOpenIDConnectProvider.html") if {
	some name in resources_of_type("AWS::IAM::OIDCProvider")
	n := count(flatten_list(name, "Properties.ClientIdList"))
	n > 100
}
