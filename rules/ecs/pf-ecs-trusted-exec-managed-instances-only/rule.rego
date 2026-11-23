package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-ecs-trusted-exec-managed-instances-only", "ERROR", name,
	"Properties.TrustedExecutionConfiguration",
	sprintf("TrustedExecutionConfiguration with RequiresCompatibilities %v; trusted execution is supported only for Amazon ECS Managed Instances", [rc]),
	"Use RequiresCompatibilities MANAGED_INSTANCES, or drop TrustedExecutionConfiguration",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-ecs-taskdefinition-trustedexecutionconfiguration.html") if {
	some name in resources_of_type("AWS::ECS::TaskDefinition")
	_pf_ecste_isolated(name)
	rc := [it.value | some it in flatten_list(name, "Properties.RequiresCompatibilities")]
	count(rc) > 0
	some v in rc
	is_string(v)
	v != "MANAGED_INSTANCES"
}

_pf_ecste_isolated(name) if {
	m := resolve(name, "Properties.TrustedExecutionConfiguration.IsolationMode")
	is_string(m)
	m != "SHARED"
}
