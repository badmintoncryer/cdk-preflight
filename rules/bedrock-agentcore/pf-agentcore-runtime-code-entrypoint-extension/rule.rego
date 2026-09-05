package cdk_preflight

import rego.v1

# EntryPoint is a free string list in the schema; the service checks the file
# extension against Runtime ("Entrypoint file type does not match your
# selected runtime"). Only the Python family is measured; NODE_22 is left alone.
violation contains make_diag_full("pf-agentcore-runtime-code-entrypoint-extension", "ERROR", name,
	"Properties.AgentRuntimeArtifact.CodeConfiguration.EntryPoint",
	sprintf("Runtime is %s but no EntryPoint element ends with .py; CreateAgentRuntime fails with \"Entrypoint file type does not match your selected runtime\"", [runtime]),
	"Point EntryPoint at the Python file to run (e.g. [\"app.py\"])",
	"https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/runtime-get-started-code-deploy-python.html") if {
	some name in resources_of_type("AWS::BedrockAgentCore::Runtime")
	runtime := resolve(name, "Properties.AgentRuntimeArtifact.CodeConfiguration.Runtime")
	is_string(runtime)
	startswith(runtime, "PYTHON_")
	entries := resolve(name, "Properties.AgentRuntimeArtifact.CodeConfiguration.EntryPoint")
	is_array(entries)
	count(entries) > 0
	every e in entries {
		is_string(e)
		not endswith(e, ".py")
	}
}
