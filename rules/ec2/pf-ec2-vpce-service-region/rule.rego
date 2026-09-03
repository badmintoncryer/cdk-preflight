package cdk_preflight

import rego.v1

_pf_ec2vsr_url := "https://docs.aws.amazon.com/vpc/latest/privatelink/privatelink-access-aws-services.html"

# Only com.amazonaws.<region>.<service> names where the third segment is
# region-shaped; names like com.amazonaws.s3-global.accesspoint stay out.
_pf_ec2vsr_parts(name) := parts if {
	sn := resolve(name, "Properties.ServiceName")
	is_string(sn)
	parts := split(sn, ".")
	count(parts) == 4
	parts[0] == "com"
	parts[1] == "amazonaws"
	regex.match(`^[a-z]{2}(-[a-z]+)+-[0-9]+$`, parts[2])
}

_pf_ec2vsr_absent(name, key) if {
	props := input.resources[name].properties
	is_object(props)
	object.get(props, key, "__pf_absent") == "__pf_absent"
}

violation contains make_diag_full("pf-ec2-vpce-service-region", "ERROR", name,
	"Properties.ServiceName",
	sprintf("Endpoint service '%s' names region %s but this stack deploys to %s; without ServiceRegion the lookup is regional and the create fails", [concat(".", parts), parts[2], region]),
	"Use com.amazonaws.<deploy-region>.<service>, or set ServiceRegion for cross-region PrivateLink",
	_pf_ec2vsr_url) if {
	region := data.cdk_preflight.deploy_region
	some name in resources_of_type("AWS::EC2::VPCEndpoint")
	parts := _pf_ec2vsr_parts(name)
	parts[2] != region
	_pf_ec2vsr_absent(name, "ServiceRegion")
}
