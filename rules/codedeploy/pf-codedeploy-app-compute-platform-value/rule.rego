package cdk_preflight

import rego.v1

# The bundled engine knows this enum but lists only ECS/Lambda/Server and
# reports the miss as W3030, which does not block a synth; the service takes a
# fourth value (Kubernetes) the engine has never heard of.
violation contains make_diag_full("pf-codedeploy-app-compute-platform-value", "ERROR", name,
	"Properties.ComputePlatform",
	sprintf("ComputePlatform '%v' is not a CodeDeploy compute platform; the application create fails with \"ComputePlatform '%v' is not valid. Valid values are [Server, Lambda, ECS, Kubernetes]\"", [cp, cp]),
	"Use Server, Lambda, ECS or Kubernetes - EC2 and on-premises deployments are the Server platform",
	"https://docs.aws.amazon.com/codedeploy/latest/APIReference/API_CreateApplication.html") if {
	some name in resources_of_type("AWS::CodeDeploy::Application")
	cp := resolve(name, "Properties.ComputePlatform")
	_pf_codedeploylib_lit(cp)
	not cp in {"Server", "Lambda", "ECS", "Kubernetes"}
}
