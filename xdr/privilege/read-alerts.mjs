import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const fixtureUrl = new URL('../fixtures/privilege.json', import.meta.url);
const fieldNames = ['timestamp', 'srcip', 'srcuser', 'level', 'description'];
const asText = (value) => typeof value === 'string' ? value : null;

export async function readAlerts() {
  const fixture = JSON.parse(await readFile(fixtureUrl, 'utf8'));
  if (fixture?.schema !== 'aleph.xdr.fixture.v1' || fixture.moduleKey !== 'privilege'
      || !Array.isArray(fixture.alerts)) {
    throw new Error('권한 경보 파일 형식 오류');
  }
  return fixture.alerts.map((a) => ({
    timestamp: asText(a?.timestamp),
    srcip: asText(a?.data?.srcip),
    srcuser: asText(a?.data?.srcuser),
    level: typeof a?.rule?.level === 'number' && Number.isFinite(a.rule.level) ? a.rule.level : null,
    description: asText(a?.rule?.description),
  }));
}

const isMain = process.argv[1] && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url));
if (isMain) {
  try {
    const rows = await readAlerts();
    const missingFields = Object.fromEntries(fieldNames.map(field => [field, rows.filter(row => row[field] === null).length]));
    console.log(JSON.stringify({ extractedCount: rows.length, missingFields }, null, 2));
  } catch {
    console.error('권한 경보를 읽지 못했습니다.');
    process.exitCode = 1;
  }
}
