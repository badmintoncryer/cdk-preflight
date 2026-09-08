package cdk_preflight

import rego.v1

_pf_lgdof_formats := {"json", "plain", "w3c", "raw", "parquet"}

violation contains make_diag_full("pf-logs-delivery-destination-output-format-enum", "ERROR", name,
	"Properties.OutputFormat",
	sprintf("OutputFormat '%s' is not a delivery output format; PutDeliveryDestination fails with \"failed to satisfy constraint: Member must satisfy enum value set: [w3c, raw, json, plain, parquet]\"", [f]),
	"Use json, plain, w3c, raw or parquet",
	"https://docs.aws.amazon.com/AmazonCloudWatch/latest/APIReference/API_PutDeliveryDestination.html") if {
	some name in resources_of_type("AWS::Logs::DeliveryDestination")
	f := resolve(name, "Properties.OutputFormat")
	is_string(f)
	not f in _pf_lgdof_formats
}
