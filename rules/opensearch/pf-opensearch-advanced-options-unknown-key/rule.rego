package cdk_preflight

import rego.v1

# Allowlist, hence WARN: the set is the documented one (2026-09-24) and AWS can
# add a key without telling us, which would turn an ERROR into a false positive.
_pf_osao_known := {
	"rest.action.multi.allow_explicit_index",
	"indices.fielddata.cache.size",
	"indices.query.bool.max_clause_count",
	"override_main_response_version",
	"plugins.query.datasources.enabled",
}

violation contains make_diag_full("pf-opensearch-advanced-options-unknown-key", "WARN", name,
	"Properties.AdvancedOptions",
	sprintf("AdvancedOptions key \"%v\" is not one of the keys the service knows; CreateDomain answers \"Unrecognized advanced option\"", [k]),
	"Remove the key, or check the spelling against the CreateDomain reference",
	"https://docs.aws.amazon.com/opensearch-service/latest/APIReference/API_CreateDomain.html") if {
	some name in _pf_os_domains
	opts := _pf_os_at(name, "AdvancedOptions")
	is_object(opts)
	some k, _v in opts
	not k in _pf_osao_known
}
