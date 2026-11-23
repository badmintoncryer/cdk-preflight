package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-ecs-attestation-policy-confidential-only", "ERROR", name,
	"Properties.TrustedExecutionConfiguration.AttestationPolicy",
	sprintf("AttestationPolicy with IsolationMode %v; the policy is valid only with CONFIDENTIAL_SANDBOX", [m]),
	"Drop AttestationPolicy, or use IsolationMode CONFIDENTIAL_SANDBOX",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-ecs-taskdefinition-trustedexecutionconfiguration.html") if {
	some name in resources_of_type("AWS::ECS::TaskDefinition")
	resolve(name, "Properties.TrustedExecutionConfiguration.AttestationPolicy") != null
	m := _pf_ecapc_mode(name)
	m != "CONFIDENTIAL_SANDBOX"
}

_pf_ecapc_mode(name) := m if {
	m := resolve(name, "Properties.TrustedExecutionConfiguration.IsolationMode")
	is_string(m)
} else := "SHARED"
