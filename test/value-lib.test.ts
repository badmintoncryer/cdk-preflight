/**
 * rules/_lib/value.rego: 省略・null・真偽値・マーカーは数値にならない（＝ルールが降りる）。
 */
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { loadEngine, validateTemplate } from '../src/private/enforce';
import { BUNDLED_LIBS } from '../src/rules.generated';

const engine = loadEngine();
const probe = `package cdk_preflight

import rego.v1

violation contains make_diag_full("probe", "WARN", name, "Properties", sprintf("%v=%v", [k, n]), "f", "u") if {
	some name in resources_of_type("AWS::SNS::Topic")
	props := input.resources[name].properties
	some k in ["Num", "Str", "Null", "Bool", "Missing", "Word", "Marker"]
	n := _pf_onum(props, k)
}
`;

test('_pf_onum reads only literal numbers and numeric strings', () => {
  const inst = new engine.RegoEngine({
    customRules: [
      ...BUNDLED_LIBS.map((l) => ({ name: l.name, content: l.rego })),
      { name: 'probe', content: probe },
    ],
  });
  const tpl = {
    Parameters: { P: { Type: 'String' } },
    Resources: {
      T: {
        Type: 'AWS::SNS::Topic',
        Properties: { Num: 5, Str: '7', Null: null, Bool: true, Word: 'abc', Marker: { Ref: 'P' } },
      },
    },
  };
  const file = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'cdkpf-value-')), 't.json');
  fs.writeFileSync(file, JSON.stringify(tpl));
  const report = validateTemplate(inst, new engine.TemplateFile(file), {});
  const got = (report.diagnostics ?? []).filter((d: any) => d.ruleId === 'probe').map((d: any) => d.message).sort();
  expect(got).toEqual(['Num=5', 'Str=7']);
});
