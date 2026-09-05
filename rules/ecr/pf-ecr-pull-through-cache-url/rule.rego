package cdk_preflight

import rego.v1

_pf_ecrptcu_url := "https://docs.aws.amazon.com/AmazonECR/latest/APIReference/API_CreatePullThroughCacheRule.html"

_pf_ecrptcu_fix := "Use one of public.ecr.aws, registry.k8s.io, quay.io, registry-1.docker.io, ghcr.io, registry.gitlab.com, cgr.dev, <name>.azurecr.io or <account>.dkr.ecr.<region>.amazonaws.com — lowercase, no scheme and no path"

violation contains make_diag_full("pf-ecr-pull-through-cache-url", "ERROR", name,
	"Properties.UpstreamRegistryUrl",
	sprintf("'%s' is not a supported upstream registry endpoint; CreatePullThroughCacheRule fails with \"The upstream registry URL %s is invalid\"", [url, url]),
	_pf_ecrptcu_fix, _pf_ecrptcu_url) if {
	some name in resources_of_type("AWS::ECR::PullThroughCacheRule")
	url := resolve(name, "Properties.UpstreamRegistryUrl")
	is_string(url)
	not input.resources[url]
	not _pf_ecrlib_ptc_registry(url)
}

violation contains make_diag_full("pf-ecr-pull-through-cache-url", "ERROR", name,
	"Properties.UpstreamRegistryUrl",
	sprintf("'%s' is the registry this rule is created in; CreatePullThroughCacheRule fails with \"Upstream registry URL cannot be the same as the cache registry\"", [url]),
	_pf_ecrptcu_fix, _pf_ecrptcu_url) if {
	some name in resources_of_type("AWS::ECR::PullThroughCacheRule")
	url := resolve(name, "Properties.UpstreamRegistryUrl")
	is_string(url)
	url == sprintf("%s.dkr.ecr.%s.amazonaws.com", [data.cdk_preflight.deploy_account, data.cdk_preflight.deploy_region])
}
