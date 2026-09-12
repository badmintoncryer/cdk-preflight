package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-batch-sp-quota-share-idle-strategy-value", "ERROR", name,
	"Properties.QuotaSharePolicy.IdleResourceAssignmentStrategy",
	sprintf("IdleResourceAssignmentStrategy is %v (\"Idle resource assignment strategy must be one of [FIFO].\")", [v]),
	"Set IdleResourceAssignmentStrategy: FIFO",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-batch-schedulingpolicy-quotasharepolicy.html") if {
	some name in resources_of_type("AWS::Batch::SchedulingPolicy")
	q := _pf_batch_get(name, "QuotaSharePolicy")
	v := _pf_batch_oget(q, "IdleResourceAssignmentStrategy")
	_pf_batch_lit(v)
	v != "FIFO"
}
