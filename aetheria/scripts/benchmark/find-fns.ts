import * as fs from 'fs';
import * as path from 'path';
import { detectInCode } from '../../src/lib/analysis/detect';
import { FalsePositiveDetector } from '../../src/lib/false-positives/detector';

async function main() {
  const csv = fs.readFileSync('vendor/fp/owasp-benchmark/expectedresults-1.2.csv','utf8');
  const lines = csv.trim().split('\n').slice(1);
  const srcDir = 'vendor/fp/owasp-benchmark/src/main/java/org/owasp/benchmark/testcode';
  const fp = new FalsePositiveDetector();
  await fp.init();
  const fns: string[] = [];
  for (const line of lines) {
    const [name, cat, expected] = line.split(',');
    if (expected !== 'true') continue;
    if (!['cmdi','sqli','xss','pathtraver'].includes(cat)) continue;
    const file = path.join(srcDir, name + '.java');
    if (!fs.existsSync(file)) continue;
    const code = fs.readFileSync(file, 'utf8');
    const findings = await detectInCode(code, { fileName: name + '.java', scanLevel: 'STATIC' });
    const kept = findings.filter(f => fp.checkVulnerability(f, code));
    if (kept.length === 0) fns.push(name + ' (' + cat + ')');
  }
  console.log('FNs:', fns.length);
  console.log(fns.join('\n'));
}
main();
