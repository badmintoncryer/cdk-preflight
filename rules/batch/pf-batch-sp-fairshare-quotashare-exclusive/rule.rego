package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-batch-sp-fairshare-quotashare-exclusive", "ERROR", name,
	"Properties.QuotaSharePolicy",
	"the scheduling policy sets both FairsharePolicy and QuotaSharePolicy (\"A scheduling policy can have either fairsharePolicy or quotaSharePolicy\")",
	"Keep one of FairsharePolicy and QuotaSharePolicy",
	"https://docs.aws.amazon.com/batch/latest/APIReference/API_CreateSchedulingPolicy.html") if {
	some name in resources_of_type("AWS::Batch::SchedulingPolicy")
	_pf_batch_has(name, "FairsharePolicy")
	_pf_batch_has(name, "QuotaSharePolicy")
}
