package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-iot-jobtemplate-document-exactly-one", "ERROR", name,
	"Properties.Document",
	"the job template sets both Document and DocumentSource; CreateJobTemplate answers \"Job document and job document source cannot be specified at the same time.\"",
	"Keep the inline Document or the DocumentSource URL, not both",
	"https://docs.aws.amazon.com/iot/latest/apireference/API_CreateJobTemplate.html") if {
	some name in resources_of_type("AWS::IoT::JobTemplate")
	_pf_iotlib_has(name, "Document")
	_pf_iotlib_has(name, "DocumentSource")
}

violation contains make_diag_full("pf-iot-jobtemplate-document-exactly-one", "ERROR", name,
	"Properties.Document",
	"the job template sets neither Document nor DocumentSource; CreateJobTemplate answers \"Neither job document nor job document source is specified.\"",
	"Add an inline Document or a DocumentSource URL",
	"https://docs.aws.amazon.com/iot/latest/apireference/API_CreateJobTemplate.html") if {
	some name in resources_of_type("AWS::IoT::JobTemplate")
	not _pf_iotlib_has(name, "Document")
	not _pf_iotlib_has(name, "DocumentSource")
}
