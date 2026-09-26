package cdk_preflight

import rego.v1

# The bundled engine sees this enum, but only as W3030/WARN, so nothing blocks the
# deploy (strict promotes ERROR/FATAL alone) — upstream: pending-engine. What
# actually stops the deploy is CloudFormation's server-side validation against the
# raw registry schema, which names no property at all: measured 2026-09-27, the
# stack holds three events and not one of them is about a resource. The service's
# own answer (BadRequestException: Invalid request body) never appears on this
# path.
violation contains make_diag_full("pf-grafana-ws-data-sources-enum", "ERROR", name,
	"Properties.DataSources",
	sprintf("DataSources entry \"%v\" is not a Grafana data source type; CloudFormation refuses the deploy with \"Validation failed with 1 error(s). Call DescribeEvents to retrieve the full list of issues with resource and property details\", which names neither the resource nor the property", [v]),
	"Use one of AMAZON_OPENSEARCH_SERVICE, ATHENA, CLOUDWATCH, PROMETHEUS, REDSHIFT, SITEWISE, TIMESTREAM, TWINMAKER, XRAY",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-grafana-workspace.html") if {
	some name in resources_of_type("AWS::Grafana::Workspace")
	some v in _pf_grafana_strings(_pf_grafana_props(name), "DataSources")
	not v in {"AMAZON_OPENSEARCH_SERVICE", "ATHENA", "CLOUDWATCH", "PROMETHEUS", "REDSHIFT", "SITEWISE", "TIMESTREAM", "TWINMAKER", "XRAY"}
}
