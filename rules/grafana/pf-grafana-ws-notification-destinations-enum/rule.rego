package cdk_preflight

import rego.v1

# SNS is the only destination Grafana can be given, on both the CloudFormation and
# the API side. The bundled engine sees the enum as W3030/WARN only, so nothing
# blocks the deploy — upstream: pending-engine. The deploy is stopped instead by
# CloudFormation's server-side validation against the raw registry schema, whose
# sentence names neither the resource nor the property.
violation contains make_diag_full("pf-grafana-ws-notification-destinations-enum", "ERROR", name,
	"Properties.NotificationDestinations",
	sprintf("NotificationDestinations entry \"%v\" is not SNS, the only destination Grafana accepts; CloudFormation refuses the deploy with \"Validation failed with 1 error(s). Call DescribeEvents to retrieve the full list of issues with resource and property details\", which names neither the resource nor the property", [v]),
	"Use SNS, or leave NotificationDestinations out",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-grafana-workspace.html") if {
	some name in resources_of_type("AWS::Grafana::Workspace")
	some v in _pf_grafana_strings(_pf_grafana_props(name), "NotificationDestinations")
	v != "SNS"
}
