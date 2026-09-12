package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-batch-sp-share-distribution-max", "ERROR", name,
	"Properties.FairsharePolicy.ShareDistribution",
	sprintf("the fair-share policy declares %v share identifiers (\"ShareDistribution size cannot be greater than 500.\")", [n]),
	"Keep at most 500 share identifiers in one scheduling policy",
	"https://docs.aws.amazon.com/batch/latest/APIReference/API_ShareAttributes.html") if {
	some name in resources_of_type("AWS::Batch::SchedulingPolicy")
	n := count(flatten_list(name, "Properties.FairsharePolicy.ShareDistribution"))
	n > 500
}
