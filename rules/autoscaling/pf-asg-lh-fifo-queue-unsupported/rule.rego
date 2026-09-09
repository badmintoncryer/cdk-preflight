package cdk_preflight

import rego.v1

_pf_asglhfq_url := "https://docs.aws.amazon.com/autoscaling/ec2/APIReference/API_PutLifecycleHook.html"

_pf_asglhfq_fifo(name) if {
	v := resolve(name, "Properties.NotificationTargetARN")
	_pf_aslib_lit(v)
	endswith(v, ".fifo")
}

_pf_asglhfq_fifo(name) if {
	q := resolve(name, "Properties.NotificationTargetARN")
	q in resources_of_type("AWS::SQS::Queue")
	resolve(q, "Properties.FifoQueue") == true
}

violation contains make_diag_full("pf-asg-lh-fifo-queue-unsupported", "ERROR", name,
	"Properties.NotificationTargetARN",
	"the notification target is a FIFO queue; FIFO queues are not compatible with lifecycle hooks and the hook create fails with \"Unable to publish test message to notification target\"",
	"Point NotificationTargetARN at a standard queue, an SNS topic or a Lambda function", _pf_asglhfq_url) if {
	some name in resources_of_type("AWS::AutoScaling::LifecycleHook")
	_pf_asglhfq_fifo(name)
}
