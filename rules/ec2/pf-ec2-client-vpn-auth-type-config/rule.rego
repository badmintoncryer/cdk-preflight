package cdk_preflight

import rego.v1

_pf_cvpnauth_url := "https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_CreateClientVpnEndpoint.html"

# Each authentication type carries exactly one sub-block; the schema keeps every
# sub-block optional, so a type/sub-block mismatch only surfaces at CreateClientVpnEndpoint.
_pf_cvpnauth_block := {
	"certificate-authentication": "MutualAuthentication",
	"directory-service-authentication": "ActiveDirectory",
	"federated-authentication": "FederatedAuthentication",
}

_pf_cvpnauth_has(opt, key) if object.get(opt, key, "__pf_absent") != "__pf_absent"

violation contains make_diag_full("pf-ec2-client-vpn-auth-type-config", "ERROR", name,
	sprintf("Properties.AuthenticationOptions.%d.%s", [item.index, want]),
	sprintf("AuthenticationOptions.Type '%s' requires the %s block", [t, want]),
	sprintf("Add the %s block, or change Type", [want]), _pf_cvpnauth_url) if {
	some name in resources_of_type("AWS::EC2::ClientVpnEndpoint")
	some item in flatten_list(name, "Properties.AuthenticationOptions")
	t := object.get(item.value, "Type", null)
	want := _pf_cvpnauth_block[t]
	not _pf_cvpnauth_has(item.value, want)
}

violation contains make_diag_full("pf-ec2-client-vpn-auth-type-config", "ERROR", name,
	sprintf("Properties.AuthenticationOptions.%d.%s", [item.index, extra]),
	sprintf("AuthenticationOptions.Type '%s' does not take the %s block", [t, extra]),
	sprintf("Remove the %s block, or change Type", [extra]), _pf_cvpnauth_url) if {
	some name in resources_of_type("AWS::EC2::ClientVpnEndpoint")
	some item in flatten_list(name, "Properties.AuthenticationOptions")
	t := object.get(item.value, "Type", null)
	want := _pf_cvpnauth_block[t]
	some other, extra in _pf_cvpnauth_block
	other != t
	extra != want
	_pf_cvpnauth_has(item.value, extra)
}
