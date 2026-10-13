import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const fixtureUrl = new URL('../fixtures/known-cve.json', import.meta.url);
const fields = ['timestamp', 'srcip', 'srcuser', 'level', 'description'];
const txt = (v) => typeof v === 'string' ? v : null;
const num = (v) => typeof v === 'number' && Number.isFinite(v) ? v : null;

export async function readAlerts() {
  const fixture = JSON.parse(await readFile(fixtureUrl, 'utf8'));
  if (fixture?.schema !== 'aleph.xdr.fixture.v1' ||
      fixture.moduleKey !== 'known-cve' || !Array.isArray(fixture.alerts)) {
    throw new Error('경보 파일 형식 오류');
  }
  return fixture.alerts.map((a) => ({
    timestamp: txt(a?.timestamp), srcip: txt(a?.data?.srcip),
    srcuser: txt(a?.data?.srcuser), level: num(a?.rule?.level),
    description: txt(a?.rule?.description),
  }));
}

const main = process.argv[1] && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url));
if (main) {
  try {
    const rows = await readAlerts();
    console.log(JSON.stringify({ extractedCount: rows.length,
      missingFields: Object.fromEntries(fields.map((f) => [f, rows.filter((r) => r[f] === null).length])) }, null, 2));
  } catch {
    console.error('경보 읽기 실패');
    process.exitCode = 1;
  }
}
