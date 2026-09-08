package cdk_preflight

import rego.v1

# The doc's per-subtype parameter table: which RequestParameters are mandatory
# depends on the subtype, which no schema expresses.
_pf_agvisrp_required("EventBridge-PutEvents") := {"Detail", "DetailType", "Source"}

_pf_agvisrp_required("SQS-SendMessage") := {"QueueUrl", "MessageBody"}

_pf_agvisrp_required("SQS-ReceiveMessage") := {"QueueUrl"}

_pf_agvisrp_required("SQS-DeleteMessage") := {"QueueUrl", "ReceiptHandle"}

_pf_agvisrp_required("SQS-PurgeQueue") := {"QueueUrl"}

_pf_agvisrp_required("AppConfig-GetConfiguration") := {"Application", "Environment", "Configuration", "ClientId"}

_pf_agvisrp_required("Kinesis-PutRecord") := {"StreamName", "Data", "PartitionKey"}

_pf_agvisrp_required("StepFunctions-StartExecution") := {"StateMachineArn"}

_pf_agvisrp_required("StepFunctions-StartSyncExecution") := {"StateMachineArn"}

_pf_agvisrp_required("StepFunctions-StopExecution") := {"ExecutionArn"}

_pf_agvisrp_present(rp, p) if {
	some k, _ in rp
	k == p
}

violation contains make_diag_full("pf-apigwv2-integration-subtype-required-parameters", "ERROR", name,
	"Properties.RequestParameters",
	sprintf("IntegrationSubtype %s requires the request parameter %s; the integration create fails with \"Operation: %s requires enabling passthrough, or defining all of the following parameters\"", [sub, p, sub]),
	sprintf("Add \"%s\" to RequestParameters", [p]),
	"https://docs.aws.amazon.com/apigateway/latest/developerguide/http-api-develop-integrations-aws-services-reference.html") if {
	some name in resources_of_type("AWS::ApiGatewayV2::Integration")
	sub := resolve(name, "Properties.IntegrationSubtype")
	req := _pf_agvisrp_required(sub)
	rp := resolve(name, "Properties.RequestParameters")
	is_object(rp)
	some p in req
	not _pf_agvisrp_present(rp, p)
}
