package cdk_preflight

import rego.v1

_pf_cf_ogmember_ids(name) := {id |
	some it in flatten_list(name, "Properties.DistributionConfig.Origins")
	id := object.get(it.value, "Id", null)
	is_string(id)
}

violation contains make_diag_full("pf-cloudfront-origin-group-member-origin", "ERROR", name,
	sprintf("Properties.DistributionConfig.OriginGroups.Items.%d.Members", [g.index]),
	sprintf("Origin group member '%s' does not match any origin Id in the distribution", [oid]),
	"Point every origin group member at the Id of an origin declared in Origins",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-cloudfront-distribution-origingroup.html") if {
	some name in resources_of_type("AWS::CloudFront::Distribution")
	some g in flatten_list(name, "Properties.DistributionConfig.OriginGroups.Items")
	members := object.get(object.get(g.value, "Members", {}), "Items", [])
	some m in members
	oid := object.get(m, "OriginId", null)
	is_string(oid)
	not oid in _pf_cf_ogmember_ids(name)
}
