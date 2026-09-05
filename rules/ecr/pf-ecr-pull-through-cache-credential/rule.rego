package cdk_preflight

import rego.v1

_pf_ecrptcc_url := "https://docs.aws.amazon.com/AmazonECR/latest/APIReference/API_CreatePullThroughCacheRule.html"

_pf_ecrptcc_fix := "Give docker-hub / ghcr.io / registry.gitlab.com / cgr.dev / *.azurecr.io a CredentialArn (a Secrets Manager secret named ecr-pullthroughcache/... in this account and region), and leave CredentialArn off public.ecr.aws, registry.k8s.io and quay.io"

_pf_ecrptcc_has(name, key) if {
	props := input.resources[name].properties
	is_object(props)
	object.get(props, key, "__pf_absent") != "__pf_absent"
}

violation contains make_diag_full("pf-ecr-pull-through-cache-credential", "ERROR", name,
	"Properties.CredentialArn",
	sprintf("'%s' requires authentication but CredentialArn is missing; CreatePullThroughCacheRule fails with \"The specified upstream registry requires authentication\"", [url]),
	_pf_ecrptcc_fix, _pf_ecrptcc_url) if {
	some name in resources_of_type("AWS::ECR::PullThroughCacheRule")
	url := resolve(name, "Properties.UpstreamRegistryUrl")
	_pf_ecrlib_ptc_needs_secret(url)
	not _pf_ecrptcc_has(name, "CredentialArn")
}

violation contains make_diag_full("pf-ecr-pull-through-cache-credential", "ERROR", name,
	"Properties.CredentialArn",
	sprintf("'%s' takes no credentials but CredentialArn is set; CreatePullThroughCacheRule fails with \"The specified upstream registry doesn't require authentication\"", [url]),
	_pf_ecrptcc_fix, _pf_ecrptcc_url) if {
	some name in resources_of_type("AWS::ECR::PullThroughCacheRule")
	url := resolve(name, "Properties.UpstreamRegistryUrl")
	_pf_ecrlib_ptc_open_url[url]
	_pf_ecrptcc_has(name, "CredentialArn")
}

violation contains make_diag_full("pf-ecr-pull-through-cache-credential", "ERROR", name,
	"Properties.CustomRoleArn",
	sprintf("CustomRoleArn is set but '%s' authenticates with a Secrets Manager secret; CreatePullThroughCacheRule fails with \"Upstream registry URL and provided credential type do not match\"", [url]),
	_pf_ecrptcc_fix, _pf_ecrptcc_url) if {
	some name in resources_of_type("AWS::ECR::PullThroughCacheRule")
	url := resolve(name, "Properties.UpstreamRegistryUrl")
	is_string(url)
	_pf_ecrlib_ptc_registry(url) != "ecr"
	_pf_ecrptcc_has(name, "CustomRoleArn")
}

# The secret must live next to the rule: ECR reads it with the service-linked
# role in the rule's own account and region.
violation contains make_diag_full("pf-ecr-pull-through-cache-credential", "ERROR", name,
	"Properties.CredentialArn",
	sprintf("the secret is in region '%s' but the rule deploys to '%s'; CreatePullThroughCacheRule fails with \"Please verify the secret exists in the same region and account that the pullthrough cache rule will be created in\"", [parts[3], region]),
	_pf_ecrptcc_fix, _pf_ecrptcc_url) if {
	region := data.cdk_preflight.deploy_region
	some name in resources_of_type("AWS::ECR::PullThroughCacheRule")
	parts := _pf_ecrlib_arn(resolve(name, "Properties.CredentialArn"))
	parts[2] == "secretsmanager"
	parts[3] != region
}

violation contains make_diag_full("pf-ecr-pull-through-cache-credential", "ERROR", name,
	"Properties.CredentialArn",
	sprintf("the secret belongs to account %s but the rule deploys to account %s; CreatePullThroughCacheRule fails with \"Please verify the secret exists in the same region and account that the pullthrough cache rule will be created in\"", [parts[4], account]),
	_pf_ecrptcc_fix, _pf_ecrptcc_url) if {
	account := data.cdk_preflight.deploy_account
	some name in resources_of_type("AWS::ECR::PullThroughCacheRule")
	parts := _pf_ecrlib_arn(resolve(name, "Properties.CredentialArn"))
	parts[2] == "secretsmanager"
	parts[4] != account
}
