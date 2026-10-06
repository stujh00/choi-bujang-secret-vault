import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { deploymentIdentity } from './deployment-identity.mjs';

const root = resolve(import.meta.dirname, '..');
const source = resolve(root, 'data.json');
const output = resolve(root, 'public', 'data.json');
const config = JSON.parse(await readFile(resolve(root, 'aleph.config.json'), 'utf8'));
if (![1, 2].includes(config.step)) {
  throw new Error('지원하지 않는 단계입니다.');
}
const data = JSON.parse(await readFile(source, 'utf8'));
if (!Array.isArray(data.notes) || data.notes.length !== 0) {
  throw new Error('메모는 정적 공개 자료에 포함할 수 없습니다.');
}
await mkdir(resolve(root, 'public'), { recursive: true });
const publicData = config.step === 1
  ? { sampleMarker: config.sampleMarker, notes: data.notes }
  : { notes: data.notes };
await writeFile(output, `${JSON.stringify(publicData)}\n`, 'utf8');
console.log('메모 없이 공개용 data.json을 생성했습니다.');
if (!process.argv.includes('--local')) {
  const identity = deploymentIdentity(process.env, config);
  await writeFile(resolve(root, 'public', 'aleph.json'),
    `${JSON.stringify(identity, null, 2)}\n`, 'utf8');
  console.log('배포 저장소·커밋·주소를 public/aleph.json에 기록했습니다.');
}
