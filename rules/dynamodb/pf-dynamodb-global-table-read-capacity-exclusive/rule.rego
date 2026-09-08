package cdk_preflight

import rego.v1

_pf_ddbgrc_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-dynamodb-globaltable-readprovisionedthroughputsettings.html"

_pf_ddbgrc_units(rp) if object.get(rp, "ReadCapacityUnits", "__pf_absent") != "__pf_absent"

_pf_ddbgrc_auto(rp) if object.get(rp, "ReadCapacityAutoScalingSettings", "__pf_absent") != "__pf_absent"

violation contains make_diag_full("pf-dynamodb-global-table-read-capacity-exclusive", "ERROR", name,
	sprintf("Properties.Replicas.%d.ReadProvisionedThroughputSettings", [r.index]),
	sprintf("Replica '%s' sets both ReadCapacityUnits and ReadCapacityAutoScalingSettings; the two are mutually exclusive", [region]),
	"Keep either the fixed ReadCapacityUnits or the autoscaling settings, not both",
	_pf_ddbgrc_url) if {
	some name in resources_of_type("AWS::DynamoDB::GlobalTable")
	some r in flatten_list(name, "Properties.Replicas")
	rp := object.get(r.value, "ReadProvisionedThroughputSettings", null)
	is_object(rp)
	_pf_ddbgrc_units(rp)
	_pf_ddbgrc_auto(rp)
	region := object.get(r.value, "Region", "<unknown>")
}

violation contains make_diag_full("pf-dynamodb-global-table-read-capacity-exclusive", "ERROR", name,
	sprintf("Properties.Replicas.%d.ReadProvisionedThroughputSettings", [r.index]),
	sprintf("Replica '%s' has an empty ReadProvisionedThroughputSettings; one of ReadCapacityUnits or ReadCapacityAutoScalingSettings is required", [region]),
	"Set ReadCapacityUnits, or ReadCapacityAutoScalingSettings, or drop the property entirely",
	_pf_ddbgrc_url) if {
	some name in resources_of_type("AWS::DynamoDB::GlobalTable")
	some r in flatten_list(name, "Properties.Replicas")
	rp := object.get(r.value, "ReadProvisionedThroughputSettings", null)
	is_object(rp)
	not _pf_ddbgrc_units(rp)
	not _pf_ddbgrc_auto(rp)
	region := object.get(r.value, "Region", "<unknown>")
}
