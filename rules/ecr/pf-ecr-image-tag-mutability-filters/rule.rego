package cdk_preflight

import rego.v1

_pf_ecrtag_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-ecr-repository.html"

_pf_ecrtag_fix := "Pair ImageTagMutabilityExclusionFilters with MUTABLE_WITH_EXCLUSION or IMMUTABLE_WITH_EXCLUSION; plain MUTABLE / IMMUTABLE takes no filters"

_pf_ecrtag_exclusion := {"MUTABLE_WITH_EXCLUSION", "IMMUTABLE_WITH_EXCLUSION"}

_pf_ecrtag_has_filters(name) if {
	f := object.get(input.resources[name].properties, "ImageTagMutabilityExclusionFilters", null)
	is_array(f)
	count(f) > 0
}

violation contains make_diag_full("pf-ecr-image-tag-mutability-filters", "ERROR", name,
	"Properties.ImageTagMutabilityExclusionFilters",
	sprintf("ImageTagMutability is '%s' but exclusion filters are set; the create call fails with \"ImageTagMutabilityExclusionFilters are not allowed when imageTagMutability is set to %s\"", [m, m]),
	_pf_ecrtag_fix, _pf_ecrtag_url) if {
	some t in _pf_ecrlib_repo_types
	some name in resources_of_type(t)
	m := resolve(name, "Properties.ImageTagMutability")
	m in {"MUTABLE", "IMMUTABLE"}
	_pf_ecrtag_has_filters(name)
}

violation contains make_diag_full("pf-ecr-image-tag-mutability-filters", "ERROR", name,
	"Properties.ImageTagMutabilityExclusionFilters",
	sprintf("ImageTagMutability is '%s' but no exclusion filters are set; the create call fails with \"ImageTagMutabilityExclusionFilters can't be null when imageTagMutability is set to %s\"", [m, m]),
	_pf_ecrtag_fix, _pf_ecrtag_url) if {
	some t in _pf_ecrlib_repo_types
	some name in resources_of_type(t)
	m := resolve(name, "Properties.ImageTagMutability")
	m in _pf_ecrtag_exclusion
	not _pf_ecrtag_has_filters(name)
}
