package cdk_preflight

import rego.v1

# ponytail: only the "no system field at all" case is claimed - a criteria
# string that names @aws.* but is otherwise malformed passes the rule and is
# caught by the service.
violation contains make_diag_full("pf-logs-field-selection-criteria-syntax", "ERROR", name,
	"Properties.FieldSelectionCriteria",
	sprintf("FieldSelectionCriteria '%s' references no @aws system field; PutMetricFilter fails with \"The provided field selection criteria is invalid\"", [c]),
	"Select on a system field, e.g. @aws.region = \"us-east-1\" or @aws.account IN [\"123456789012\"]",
	"https://docs.aws.amazon.com/AmazonCloudWatch/latest/APIReference/API_PutMetricFilter.html") if {
	some name in resources_of_type("AWS::Logs::MetricFilter")
	c := resolve(name, "Properties.FieldSelectionCriteria")
	is_string(c)
	c != ""
	not contains(c, "@aws.")
}
