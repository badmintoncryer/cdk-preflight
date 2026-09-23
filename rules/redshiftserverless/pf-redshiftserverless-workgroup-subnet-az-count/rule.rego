package cdk_preflight

import rego.v1

# The zone of a subnet defined in this template. resolve() flattens Fn::Select over
# Fn::GetAZs to the region's real zone names (measured 2026-09-22), so a CDK Vpc with
# maxAzs: 2 is judged like a literal. Imported subnet ids cannot be, and the rule stays
# silent unless every subnet of the workgroup resolves to a zone.
_pf_rssaz_az(v) := az if {
	sub := _pf_rsslib_ref(v)
	sub in resources_of_type("AWS::EC2::Subnet")
	az := resolve(sub, "Properties.AvailabilityZone")
	is_string(az)
	not input.resources[az]
}

violation contains make_diag_full("pf-redshiftserverless-workgroup-subnet-az-count", "ERROR", name,
	"Properties.SubnetIds",
	sprintf("EnhancedVpcRouting is on but the subnets span only %v availability zone(s) %v; CreateWorkgroup fails with \"There aren't enough free IP addresses in subnets to allow this operation. Make sure that there are at least 37 free IP addresses in 3 subnets. Each subnet should be in a different Availability Zone.\"", [count(azs), azs]),
	"Give the workgroup subnets in at least three availability zones, each with 37 or more free addresses",
	"https://docs.aws.amazon.com/redshift/latest/mgmt/serverless-known-issues.html") if {
	some name in resources_of_type("AWS::RedshiftServerless::Workgroup")
	_pf_rsslib_true(name, "EnhancedVpcRouting")
	subs := [s | some s in flatten_list(name, "Properties.SubnetIds")]
	count(subs) > 0
	every s in subs {
		_pf_rssaz_az(s.value)
	}
	azs := {az | some s in subs; az := _pf_rssaz_az(s.value)}
	count(azs) < 3
}
