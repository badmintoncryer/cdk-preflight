package cdk_preflight

import rego.v1

# The schema gives every file type the full DOCUMENT|IMAGE|VIDEO|AUDIO enum;
# the service accepts only DOCUMENT/IMAGE for jpeg/png and VIDEO/AUDIO for
# mp4/mov (measured 2026-09-06).
_pf_bmr_allowed := {"jpeg": {"DOCUMENT", "IMAGE"}, "png": {"DOCUMENT", "IMAGE"}, "mp4": {"VIDEO", "AUDIO"}, "mov": {"VIDEO", "AUDIO"}}

violation contains make_diag_full("pf-bedrock-bda-project-modality-routing", "ERROR", name,
	sprintf("Properties.OverrideConfiguration.ModalityRouting.%s", [ft]),
	sprintf("%s files cannot be routed to %s (allowed: %v); CreateDataAutomationProject fails with \"Modality override is invalid for the given file type\"", [ft, m, _pf_bmr_allowed[ft]]),
	"Route image files to DOCUMENT or IMAGE and video files to VIDEO or AUDIO",
	"https://docs.aws.amazon.com/bedrock/latest/APIReference/API_data-automation_ModalityRoutingConfiguration.html") if {
	some name in resources_of_type("AWS::Bedrock::DataAutomationProject")
	mr := object.get(object.get(_pf_bedrocklib_props(name), "OverrideConfiguration", {}), "ModalityRouting", null)
	is_object(mr)
	some ft, m in mr
	is_string(m)
	allowed := _pf_bmr_allowed[ft]
	not allowed[m]
}
