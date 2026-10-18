package cdk_preflight

import rego.v1

# The schema puts no pattern on ResourceGatewayId, but the service takes a
# resource gateway id (rgw- and 17 characters) or its ARN only ("Value ... at
# 'resourceGatewayIdentifier' failed to satisfy constraint: Member must satisfy
# regular expression pattern"). Literal strings only; Ref / Fn::GetAtt are not
# checked.
violation contains make_diag_full("pf-vpclattice-rc-gateway-id-format", "ERROR", name,
	"Properties.ResourceGatewayId",
	sprintf("ResourceGatewayId '%s' is not a resource gateway id or ARN; the create fails with \"failed to satisfy constraint\"", [v]),
	"Use the Id of a resource gateway (rgw-...), for example Fn::GetAtt <gateway>.Id",
	"https://docs.aws.amazon.com/vpc-lattice/latest/APIReference/API_CreateResourceConfiguration.html") if {
	some name in resources_of_type("AWS::VpcLattice::ResourceConfiguration")
	v := _pf_vpcl_raw(name, ["ResourceGatewayId"])
	is_string(v)
	v != "__pf_absent"
	not regex.match(`^((rgw-[0-9a-z]{17})|(arn:[a-z0-9\-]+:vpc-lattice:[a-zA-Z0-9\-]+:\d{12}:resourcegateway/rgw-[0-9a-z]{17}))$`, v)
}
