package cdk_preflight

import rego.v1

_pf_ssmpv_url := "https://docs.aws.amazon.com/systems-manager/latest/APIReference/API_PutParameter.html"

_pf_ssmpv_fix := "Remove {{ }} from the value, fill in an empty value, use a lowercase DataType, and give aws:ec2:image parameters a String value of the form ami-0123456789abcdef0"

_pf_ssmpv_value(name) := v if {
	v := resolve(name, "Properties.Value")
	is_string(v)
}

violation contains make_diag_full("pf-ssm-parameter-value", "ERROR", name,
	"Properties.Value",
	"Value contains {{ }}; PutParameter fails with \"Parameter value can't nest another parameter. Do not use \\\"{{}}\\\" in the value.\"",
	_pf_ssmpv_fix, _pf_ssmpv_url) if {
	some name in resources_of_type("AWS::SSM::Parameter")
	v := _pf_ssmpv_value(name)
	regex.match("\\{\\{.*\\}\\}", v)
}

violation contains make_diag_full("pf-ssm-parameter-value", "ERROR", name,
	"Properties.Value",
	"Value is empty; PutParameter rejects values shorter than 1 character",
	_pf_ssmpv_fix, _pf_ssmpv_url) if {
	some name in resources_of_type("AWS::SSM::Parameter")
	_pf_ssmpv_value(name) == ""
}

_pf_ssmpv_datatypes := ["text", "aws:ec2:image", "aws:ssm:integration"]

violation contains make_diag_full("pf-ssm-parameter-value", "ERROR", name,
	"Properties.DataType",
	sprintf("DataType '%s' is not one of text, aws:ec2:image, aws:ssm:integration; PutParameter fails with \"The following data type is not supported: %s. (Data type names are all lowercase.)\"", [d, d]),
	_pf_ssmpv_fix, _pf_ssmpv_url) if {
	some name in resources_of_type("AWS::SSM::Parameter")
	d := resolve(name, "Properties.DataType")
	is_string(d)
	not d in _pf_ssmpv_datatypes
}

violation contains make_diag_full("pf-ssm-parameter-value", "ERROR", name,
	"Properties.DataType",
	"DataType aws:ec2:image needs Type String; PutParameter fails with \"The aws:ec2:image data type is not supported for the following input type: StringList\"",
	_pf_ssmpv_fix, _pf_ssmpv_url) if {
	some name in resources_of_type("AWS::SSM::Parameter")
	resolve(name, "Properties.DataType") == "aws:ec2:image"
	resolve(name, "Properties.Type") == "StringList"
}

violation contains make_diag_full("pf-ssm-parameter-value", "ERROR", name,
	"Properties.Value",
	sprintf("'%s' is not an AMI id (ami-...) but DataType is aws:ec2:image; the asynchronous AMI validation fails and the resource ends with \"Resource timed out waiting for completion\"", [v]),
	_pf_ssmpv_fix, _pf_ssmpv_url) if {
	some name in resources_of_type("AWS::SSM::Parameter")
	resolve(name, "Properties.DataType") == "aws:ec2:image"
	v := _pf_ssmpv_value(name)
	not regex.match("^ami-[0-9a-f]{8,17}$", v)
}
