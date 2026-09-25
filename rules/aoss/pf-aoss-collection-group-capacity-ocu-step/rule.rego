package cdk_preflight

import rego.v1

# The schema only says Minimum 2 on the two maxima and nothing at all on the
# two minima, so 3, 5 and 20 reach the service. 0 and 1 are deliberately left
# alone: the accepted set differs by generation and by field (NEXTGEN answers
# "Allowed values are: 0, 2, 4, 8, 16, or any multiple of 16" for a maximum,
# CLASSIC answers "1, 2, 4, 8, 16, ..." for a minimum), and a rule that guessed
# would be wrong on one of them.
_pf_aoss_cgstep_fields := {
	"MinIndexingCapacityInOcu", "MaxIndexingCapacityInOcu",
	"MinSearchCapacityInOcu", "MaxSearchCapacityInOcu",
}

violation contains make_diag_full("pf-aoss-collection-group-capacity-ocu-step", "ERROR", name,
	sprintf("Properties.CapacityLimits.%v", [f]),
	sprintf("%v is %v; CreateCollectionGroup answers \"Invalid value for %v. Allowed values are: 0, 2, 4, 8, 16, or any multiple of 16\"", [f, v, f]),
	"Use 2, 4, 8, 16 or a multiple of 16 OCUs",
	"https://docs.aws.amazon.com/opensearch-service/latest/developerguide/serverless-scaling.html") if {
	some name in resources_of_type("AWS::OpenSearchServerless::CollectionGroup")
	some f in _pf_aoss_cgstep_fields
	v := to_number(resolve(name, sprintf("Properties.CapacityLimits.%v", [f])))
	not v in {0, 1, 2, 4, 8, 16}
	v % 16 != 0
}
