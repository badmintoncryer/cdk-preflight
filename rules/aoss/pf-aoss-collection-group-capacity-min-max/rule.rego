package cdk_preflight

import rego.v1

# The schema gives the four numbers no relationship at all. Each pair is
# checked on its own and the service names the pair it rejected.
_pf_aoss_cgmm_pairs := {"Indexing", "Search"}

violation contains make_diag_full("pf-aoss-collection-group-capacity-min-max", "ERROR", name,
	sprintf("Properties.CapacityLimits.Min%vCapacityInOcu", [k]),
	sprintf("Min%vCapacityInOcu is %v and Max%vCapacityInOcu is %v; CreateCollectionGroup answers \"Invalid capacity range: min%vCapacityInOCU (%v.0) exceeds max%vCapacityInOCU (%v.0)\"", [k, mn, k, mx, k, mn, k, mx]),
	sprintf("Lower Min%vCapacityInOcu to at most Max%vCapacityInOcu, or raise the maximum", [k, k]),
	"https://docs.aws.amazon.com/opensearch-service/latest/developerguide/serverless-scaling.html") if {
	some name in resources_of_type("AWS::OpenSearchServerless::CollectionGroup")
	some k in _pf_aoss_cgmm_pairs
	mn := to_number(resolve(name, sprintf("Properties.CapacityLimits.Min%vCapacityInOcu", [k])))
	mx := to_number(resolve(name, sprintf("Properties.CapacityLimits.Max%vCapacityInOcu", [k])))
	mn > mx
}
