import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const fixtureUrl = new URL('../fixtures/web-injection.json', import.meta.url);
const FIELD_NAMES = ['timestamp', 'srcip', 'srcuser', 'level', 'description'];

const asString = (value) => (typeof value === 'string' ? value : null);
const asNumber = (value) => (typeof value === 'number' && Number.isFinite(value) ? value : null);

export async function readAlerts() {
  const fixture = JSON.parse(await readFile(fixtureUrl, 'utf8'));
  if (fixture?.schema !== 'aleph.xdr.fixture.v1'
    || fixture.moduleKey !== 'web-injection'
    || !Array.isArray(fixture.alerts)) {
    throw new Error('경보 파일 형식이 올바르지 않습니다.');
  }

  return fixture.alerts.map((alert) => ({
    timestamp: asString(alert?.timestamp),
    srcip: asString(alert?.data?.srcip),
    srcuser: asString(alert?.data?.srcuser),
    level: asNumber(alert?.rule?.level),
    description: asString(alert?.rule?.description),
  }));
}

const isMain = process.argv[1]
  && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url));

if (isMain) {
  try {
    const alerts = await readAlerts();
    const missingFields = Object.fromEntries(
      FIELD_NAMES.map((field) => [field, alerts.filter((alert) => alert[field] === null).length]),
    );
    console.log(JSON.stringify({ extractedCount: alerts.length, missingFields }, null, 2));
  } catch {
    console.error('경보 파일을 읽지 못했습니다.');
    process.exitCode = 1;
  }
}