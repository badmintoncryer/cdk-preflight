package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-logs-delivery-destination-output-format-target", "ERROR", name,
	"Properties.OutputFormat",
	"The delivery destination is a log group but OutputFormat is parquet; PutDeliveryDestination fails with \"Invalid output format value provided.\"",
	"Use json or plain for a CloudWatch Logs destination; parquet is only available for S3 destinations",
	"https://docs.aws.amazon.com/AmazonCloudWatch/latest/APIReference/API_PutDeliveryDestination.html") if {
	some name in resources_of_type("AWS::Logs::DeliveryDestination")
	parts := _pf_lglib_arn(resolve(name, "Properties.DestinationResourceArn"))
	parts[2] == "logs"
	resolve(name, "Properties.OutputFormat") == "parquet"
}
