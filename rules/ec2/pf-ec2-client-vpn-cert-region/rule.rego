package cdk_preflight

import rego.v1

_pf_ec2cvcr_url := "https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_CreateClientVpnEndpoint.html"

# デプロイ先リージョン。enforce プラグインが注入しないとき（warn モード /
# リージョン非依存アプリ）は未定義になり、このルールは黙って飛ぶ。
_pf_ec2cvcr_region := r if {
	r := data.cdk_preflight.deploy_region
	is_string(r)
	r != ""
}

violation contains make_diag_full("pf-ec2-client-vpn-cert-region", "ERROR", name,
	"Properties.ServerCertificateArn",
	sprintf("The Client VPN server certificate is in %v but the endpoint is deployed to %v; ACM certificates are region-scoped, so the lookup fails with \"Certificate not found\"", [parts[3], _pf_ec2cvcr_region]),
	sprintf("Issue or import the certificate in %v and reference that ARN", [_pf_ec2cvcr_region]),
	_pf_ec2cvcr_url) if {
	some name in resources_of_type("AWS::EC2::ClientVpnEndpoint")
	arn := resolve(name, "Properties.ServerCertificateArn")
	is_string(arn)
	parts := split(arn, ":")
	count(parts) >= 6
	parts[0] == "arn"
	parts[2] == "acm"
	parts[3] != ""
	parts[3] != _pf_ec2cvcr_region
}
