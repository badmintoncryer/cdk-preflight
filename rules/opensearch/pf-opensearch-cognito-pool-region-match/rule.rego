package cdk_preflight

import rego.v1

# The Region is inside the identifiers themselves: UserPoolId "<region>_xxxx",
# IdentityPoolId "<region>:<uuid>". Nothing else in the template says where the
# pools live, which is why no other layer can see this.
violation contains make_diag_full("pf-opensearch-cognito-pool-region-match", "ERROR", name,
	"Properties.CognitoOptions.UserPoolId",
	sprintf("the user pool is in %v but the identity pool is in %v; CreateDomain answers \"IdentityPool and UserPool should be in the same region\"", [up, ip]),
	"Point UserPoolId and IdentityPoolId at pools in the same Region",
	"https://docs.aws.amazon.com/opensearch-service/latest/developerguide/cognito-auth.html") if {
	some name in _pf_os_domains
	up := _pf_os_region_prefix(_pf_os_opt(name, "CognitoOptions", "UserPoolId"), "_")
	ip := _pf_os_region_prefix(_pf_os_opt(name, "CognitoOptions", "IdentityPoolId"), ":")
	up != ip
}
