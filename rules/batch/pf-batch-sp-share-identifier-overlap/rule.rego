package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-batch-sp-share-identifier-overlap", "ERROR", name,
	"Properties.FairsharePolicy.ShareDistribution",
	sprintf("share identifier %v is also matched by the prefix %v (\"Share identifier ... matches another share identifier ...\")", [hit, si]),
	"Remove the overlap between the wildcard prefix and the explicit share identifier",
	"https://docs.aws.amazon.com/batch/latest/userguide/create-scheduling-policy.html") if {
	some name in resources_of_type("AWS::Batch::SchedulingPolicy")
	es := flatten_list(name, "Properties.FairsharePolicy.ShareDistribution")
	some e in es
	si := _pf_batch_oget(e.value, "ShareIdentifier")
	_pf_batch_lit(si)
	endswith(si, "*")
	prefix := substring(si, 0, count(si) - 1)
	hits := [y | some x in es; y := object.get(x.value, "ShareIdentifier", null); is_string(y); y != si; startswith(y, prefix)]
	count(hits) > 0
	hit := hits[0]
}
