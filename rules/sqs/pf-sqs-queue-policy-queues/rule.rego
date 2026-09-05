package cdk_preflight

import rego.v1

_pf_sqsqp_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-sqs-queuepolicy.html"

_pf_sqsqp_fix := "List the queues with Ref (the queue URL), not Fn::GetAtt Queue.Arn"

violation contains make_diag_full("pf-sqs-queue-policy-queues", "ERROR", name,
	"Properties.Queues",
	"Queues is empty; the resource handler fails with \"Queues are required\"",
	_pf_sqsqp_fix, _pf_sqsqp_url) if {
	some name in resources_of_type("AWS::SQS::QueuePolicy")
	qs := object.get(input.resources[name].properties, "Queues", null)
	is_array(qs)
	count(qs) == 0
}

# Fn::GetAtt appears in the preprocessed document as a marker object whose
# __kind names the attribute; Ref (the URL) is "resource". Literal ARNs are
# strings.
violation contains make_diag_full("pf-sqs-queue-policy-queues", "ERROR", name,
	sprintf("Properties.Queues.%d", [i]),
	"Queues entry is the queue ARN (Fn::GetAtt Queue.Arn) but QueuePolicy expects the queue URL; the resource handler fails with \"The address arn:aws:sqs:... is not valid for this endpoint.\"",
	_pf_sqsqp_fix, _pf_sqsqp_url) if {
	some name in resources_of_type("AWS::SQS::QueuePolicy")
	qs := object.get(input.resources[name].properties, "Queues", null)
	is_array(qs)
	some i, q in qs
	is_object(q)
	object.get(q, "__kind", null) == "getatt:Arn"
}

violation contains make_diag_full("pf-sqs-queue-policy-queues", "ERROR", name,
	sprintf("Properties.Queues.%d", [i]),
	sprintf("Queues entry '%s' is an ARN but QueuePolicy expects the queue URL (https://sqs.<region>.amazonaws.com/<account>/<name>); the resource handler fails with \"The address ... is not valid for this endpoint.\"", [q]),
	_pf_sqsqp_fix, _pf_sqsqp_url) if {
	some name in resources_of_type("AWS::SQS::QueuePolicy")
	qs := object.get(input.resources[name].properties, "Queues", null)
	is_array(qs)
	some i, q in qs
	is_string(q)
	startswith(q, "arn:")
}
