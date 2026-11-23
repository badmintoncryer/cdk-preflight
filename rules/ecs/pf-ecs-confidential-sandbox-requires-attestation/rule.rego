package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-ecs-confidential-sandbox-requires-attestation", "ERROR", name,
	"Properties.TrustedExecutionConfiguration.AttestationPolicy",
	"IsolationMode CONFIDENTIAL_SANDBOX without AttestationPolicy; the policy is required in that mode",
	"Add a base64-encoded AttestationPolicy, or use ISOLATED_SANDBOX",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-ecs-taskdefinition-trustedexecutionconfiguration.html") if {
	some name in resources_of_type("AWS::ECS::TaskDefinition")
	resolve(name, "Properties.TrustedExecutionConfiguration.IsolationMode") == "CONFIDENTIAL_SANDBOX"
	not _pf_eccsa_has(name)
}

_pf_eccsa_has(name) if resolve(name, "Properties.TrustedExecutionConfiguration.AttestationPolicy") != null
