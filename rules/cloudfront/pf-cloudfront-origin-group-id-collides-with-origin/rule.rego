package cdk_preflight

import rego.v1

_pf_cf_origin_group_id_collides_with_origin_fix := "Give the origin group an Id that no origin uses"

_pf_cf_origin_group_id_collides_with_origin_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cloudfront-distribution-distributionconfig.html"

violation contains make_diag_full("pf-cloudfront-origin-group-id-collides-with-origin", "ERROR", name, g.path,
	sprintf("origin group Id %v collides with an origin Id", [gid]),
	_pf_cf_origin_group_id_collides_with_origin_fix, _pf_cf_origin_group_id_collides_with_origin_url) if {
	some name in resources_of_type("AWS::CloudFront::Distribution")
	some g in _pf_cflib_origin_groups(name)
	gid := object.get(g.value, "Id", null)
	is_string(gid)
	oids := {i | some o in _pf_cflib_origins(name); i := object.get(o.value, "Id", null); is_string(i)}
	gid in oids
}
