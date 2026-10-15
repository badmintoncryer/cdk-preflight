package cdk_preflight

import rego.v1

# SNS and EventBridge deliver to a queue as themselves (a service principal), and
# the key policy of the AWS managed key alias/aws/sqs cannot be changed to let them
# use it. A queue encrypted with that key therefore accepts the subscription or the
# rule target at deploy time and then drops every message sent to it. S3
# notifications are left out (PutBucketNotificationConfiguration sends a test message
# and fails the deploy), as are consumers that read the queue with their own role
# (Lambda event source mappings, Pipes, Scheduler), which the key policy allows.
_pf_sqsamk_url := "https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-key-management.html#compatibility-with-aws-services"

_pf_sqsamk_fix := "Encrypt the queue with SqsManagedSseEnabled (SSE-SQS), or with a customer managed key whose key policy lets the sending service use it"

_pf_sqsamk_queue(q) if {
	q in resources_of_type("AWS::SQS::Queue")
	k := resolve(q, "Properties.KmsMasterKeyId")
	is_string(k)
	_pf_amk_alias(k, "sqs")
}

_pf_sqsamk_sender contains [name, path, "SNS"] if {
	some name in resources_of_type("AWS::SNS::Subscription")
	resolve(name, "Properties.Protocol") == "sqs"
	path := "Properties.Endpoint"
}

_pf_sqsamk_sender contains [name, sprintf("Properties.Subscription.%d.Endpoint", [s.index]), "SNS"] if {
	some name in resources_of_type("AWS::SNS::Topic")
	some s in flatten_list(name, "Properties.Subscription")
	resolve(name, sprintf("Properties.Subscription.%d.Protocol", [s.index])) == "sqs"
}

_pf_sqsamk_sender contains [name, sprintf("Properties.Targets.%d.Arn", [t.index]), "EventBridge"] if {
	some name in resources_of_type("AWS::Events::Rule")
	some t in flatten_list(name, "Properties.Targets")
}

violation contains make_diag_full("pf-sqs-aws-managed-key-delivery", "ERROR", name, path,
	sprintf("queue '%s' is encrypted with the AWS managed key alias/aws/sqs, which %s cannot use; every message sent to it is dropped", [q, svc]),
	_pf_sqsamk_fix, _pf_sqsamk_url) if {
	some [name, path, svc] in _pf_sqsamk_sender
	q := resolve(name, path)
	_pf_sqsamk_queue(q)
}
