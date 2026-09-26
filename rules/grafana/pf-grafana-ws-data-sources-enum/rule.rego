package cdk_preflight

import rego.v1

# The bundled engine sees this enum, but only as W3030/WARN, so nothing blocks the
# deploy (strict promotes ERROR/FATAL alone) — upstream: pending-engine. The
# service's own answer is the generic BadRequestException: Invalid request body,
# which names no property.
violation contains make_diag_full("pf-grafana-ws-data-sources-enum", "ERROR", name,
	"Properties.DataSources",
	sprintf("DataSources entry \"%v\" is not a Grafana data source type; CreateWorkspace fails with \"Invalid request body\", which names no property", [v]),
	"Use one of AMAZON_OPENSEARCH_SERVICE, ATHENA, CLOUDWATCH, PROMETHEUS, REDSHIFT, SITEWISE, TIMESTREAM, TWINMAKER, XRAY",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-grafana-workspace.html") if {
	some name in resources_of_type("AWS::Grafana::Workspace")
	some v in _pf_grafana_strings(_pf_grafana_props(name), "DataSources")
	not v in {"AMAZON_OPENSEARCH_SERVICE", "ATHENA", "CLOUDWATCH", "PROMETHEUS", "REDSHIFT", "SITEWISE", "TIMESTREAM", "TWINMAKER", "XRAY"}
}
