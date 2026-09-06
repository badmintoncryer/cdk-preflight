package cdk_preflight

import rego.v1

# FilesystemConfigurations is a list of single-key union entries; the schema
# validates each entry but only CreateAgentRuntime knows that SessionStorage
# may appear once per runtime ("At most one sessionStorage configuration is
# allowed", measured 2026-09-06 with distinct mount paths).
_pf_rtss_entries(name) := [it |
	some it in flatten_list(name, "Properties.FilesystemConfigurations")
	is_object(object.get(it.value, "SessionStorage", null))
]

violation contains make_diag_full("pf-agentcore-runtime-session-storage-single", "ERROR", name,
	sprintf("Properties.FilesystemConfigurations.%d.SessionStorage", [last]),
	sprintf("FilesystemConfigurations carries %d SessionStorage entries but a runtime allows at most one; CreateAgentRuntime fails with \"At most one sessionStorage configuration is allowed\"", [count(all)]),
	"Keep a single SessionStorage entry (one MountPath); use EfsAccessPoint or S3FilesAccessPoint entries for additional mounts",
	"https://docs.aws.amazon.com/bedrock-agentcore-control/latest/APIReference/API_CreateAgentRuntime.html") if {
	some name in resources_of_type("AWS::BedrockAgentCore::Runtime")
	all := _pf_rtss_entries(name)
	count(all) > 1
	last := max([it.index | some it in all])
}
