package cdk_preflight

import rego.v1

_pf_ecrptcm_url := "https://docs.aws.amazon.com/AmazonECR/latest/APIReference/API_CreatePullThroughCacheRule.html"

_pf_ecrptcm_fix := "Set UpstreamRegistry to the registry the URL belongs to (or leave it out — ECR derives it from the URL)"

# Measured 2026-09-05: the service compares the two only when the URL belongs
# to a registry that authenticates (docker-hub, ghcr.io, registry.gitlab.com,
# cgr.dev, *.azurecr.io). A mismatch against one of the open registries is
# silently accepted, so the rule stays on the branch that really fails.
violation contains make_diag_full("pf-ecr-pull-through-cache-registry-match", "ERROR", name,
	"Properties.UpstreamRegistry",
	sprintf("UpstreamRegistry is '%s' but '%s' is the %s endpoint; CreatePullThroughCacheRule fails with \"Upstream registry URL and entered upstream registry do not match\"", [declared, url, actual]),
	_pf_ecrptcm_fix, _pf_ecrptcm_url) if {
	some name in resources_of_type("AWS::ECR::PullThroughCacheRule")
	url := resolve(name, "Properties.UpstreamRegistryUrl")
	_pf_ecrlib_ptc_needs_secret(url)
	actual := _pf_ecrlib_ptc_registry(url)
	declared := resolve(name, "Properties.UpstreamRegistry")
	is_string(declared)
	declared != actual
}
