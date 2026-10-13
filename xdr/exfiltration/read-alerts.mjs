import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const fixtureUrl = new URL('../fixtures/exfiltration.json', import.meta.url);
const FIELDS = ['timestamp', 'srcip', 'srcuser', 'level', 'description'];
const asText = value => typeof value === 'string' ? value : null;

export async function readAlerts() {
  const fixture = JSON.parse(await readFile(fixtureUrl, 'utf8'));
  if (fixture?.schema !== 'aleph.xdr.fixture.v1' || fixture.moduleKey !== 'exfiltration'
      || !Array.isArray(fixture.alerts)) {
    throw new Error('자료 반출 경보 파일 형식 오류');
  }
  return fixture.alerts.map(alert => ({
    timestamp: asText(alert?.timestamp),
    srcip: asText(alert?.data?.srcip),
    srcuser: asText(alert?.data?.srcuser),
    level: typeof alert?.rule?.level === 'number' && Number.isFinite(alert.rule.level)
      ? alert.rule.level : null,
    description: asText(alert?.rule?.description),
  }));
}

const main = process.argv[1] && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url));
if (main) {
  try {
    const rows = await readAlerts();
    const missingFields = Object.fromEntries(FIELDS.map(field =>
      [field, rows.filter(row => row[field] === null).length]));
    console.log(JSON.stringify({ extractedCount: rows.length, missingFields }, null, 2));
  } catch {
    console.error('자료 반출 경보를 읽지 못했습니다.');
    process.exitCode = 1;
  }
}
