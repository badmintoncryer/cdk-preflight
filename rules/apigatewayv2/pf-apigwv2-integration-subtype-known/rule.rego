package cdk_preflight

import rego.v1

_pf_agvisk_known := {
	"EventBridge-PutEvents",
	"SQS-SendMessage",
	"SQS-ReceiveMessage",
	"SQS-DeleteMessage",
	"SQS-PurgeQueue",
	"AppConfig-GetConfiguration",
	"Kinesis-PutRecord",
	"StepFunctions-StartExecution",
	"StepFunctions-StartSyncExecution",
	"StepFunctions-StopExecution",
}

violation contains make_diag_full("pf-apigwv2-integration-subtype-known", "ERROR", name,
	"Properties.IntegrationSubtype",
	sprintf("IntegrationSubtype '%s' is not an AWS service integration subtype; the integration create fails with \"Operation: %s is not supported.\"", [sub, sub]),
	"Use one of EventBridge-PutEvents, SQS-SendMessage/ReceiveMessage/DeleteMessage/PurgeQueue, AppConfig-GetConfiguration, Kinesis-PutRecord, StepFunctions-StartExecution/StartSyncExecution/StopExecution",
	"https://docs.aws.amazon.com/apigateway/latest/developerguide/http-api-develop-integrations-aws-services-reference.html") if {
	some name in resources_of_type("AWS::ApiGatewayV2::Integration")
	sub := resolve(name, "Properties.IntegrationSubtype")
	is_string(sub)
	not input.resources[sub]
	not sub in _pf_agvisk_known
}
