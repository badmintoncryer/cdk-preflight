#!/usr/bin/env bash
# 公開される tarball をそのまま素の CDK アプリに入れ、enforce が実際に発火するかを見る。
# テストは全部 ../src を import しているので、パッケージング側の壊れ（exports の漏れ、
# lib/rules.generated の解決失敗、bin の欠落）はこのスクリプトでしか出ない。
#   bash scripts/smoke.sh dist/js/cdk-preflight@x.y.z.jsii.tgz
set -euo pipefail

tgz="$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
cd "$work"

npm init -y >/dev/null
npm i --no-audit --no-fund --loglevel=error aws-cdk-lib constructs tsx "$tgz" >/dev/null

cat > app.ts <<'TS'
import { App, CfnResource, Stack } from 'aws-cdk-lib';
import { Preflight } from 'cdk-preflight';

const app = new App({ outdir: 'cdk.out' });
Preflight.apply(app);
const stack = new Stack(app, 'Smoke');

// 素の CDK アプリにも出てくる形。VIOLATE=1 のときだけ Timeout を上限超えにする
// （pf-lambda-timeout-max: 900 秒が上限）。
new CfnResource(stack, 'Fn', {
  type: 'AWS::Lambda::Function',
  properties: {
    Runtime: 'nodejs22.x',
    Handler: 'index.handler',
    Role: 'arn:aws:iam::123456789012:role/smoke',
    Code: { ZipFile: 'exports.handler = async () => {};' },
    Timeout: process.env.VIOLATE === '1' ? 1000 : 30,
  },
});

app.synth();
TS

fail() { echo "smoke.sh: FAIL - $1"; cat out.log; exit 1; }

echo 'smoke.sh: clean app must synth'
npx tsx app.ts >out.log 2>&1 || fail 'a clean app did not synthesize'

echo 'smoke.sh: violating app must fail synth'
if VIOLATE=1 npx tsx app.ts >out.log 2>&1; then
  fail 'the violating app synthesized'
fi
grep -q 'pf-lambda-timeout-max' out.log || fail 'expected pf-lambda-timeout-max in the output'

echo 'smoke.sh: OK'
