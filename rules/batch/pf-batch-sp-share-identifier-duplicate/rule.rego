package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-batch-sp-share-identifier-duplicate", "ERROR", name,
	"Properties.FairsharePolicy.ShareDistribution",
	sprintf("share identifier %v is declared %v times (\"Cannot have two or more identical shareIdentifiers.\")", [si, n]),
	"Declare each share identifier once",
	"https://docs.aws.amazon.com/batch/latest/userguide/create-scheduling-policy.html") if {
	some name in resources_of_type("AWS::Batch::SchedulingPolicy")
	es := flatten_list(name, "Properties.FairsharePolicy.ShareDistribution")
	some e in es
	si := _pf_batch_oget(e.value, "ShareIdentifier")
	n := count([1 | some x in es; object.get(x.value, "ShareIdentifier", null) == si])
	n > 1
}
