// The student changes this check as each stage adds an attack to the same app.
// Never return tokens, private keys, real names, or note bodies.
export async function runAttackChecks(config) {
  if (![1, 2].includes(config.step)) throw new Error('이 단계의 공격 점검을 src/attack-check.mjs에 구현해 주세요.');
  let app;
  try {
    app = new URL(config.publicAppUrl);
  } catch {
    throw new Error('aleph.config.json의 실제 배포 주소를 먼저 넣어 주세요.');
  }
  if (app.protocol !== 'https:' || app.username || app.password || app.search || app.hash
      || app.pathname !== '/' || app.hostname.endsWith('.example')) {
    throw new Error('aleph.config.json의 실제 배포 주소를 먼저 넣어 주세요.');
  }
  if (typeof config.sampleMarker !== 'string' || !config.sampleMarker) throw new Error('가상 메모의 확인 표시를 넣어 주세요.');
  const response = await fetch(new URL('/data.json', app), {
    redirect: 'error', signal: AbortSignal.timeout(10000),
  });
  let staticNoteCount;
  if (response.ok) {
    try {
      const data = await response.json();
      const validData = config.step === 1
        ? data?.sampleMarker === config.sampleMarker
        : data?.sampleMarker === undefined;
      if (validData && Array.isArray(data.notes)) {
        staticNoteCount = data.notes.length;
      }
    } catch {
      // A non-JSON response is not a successful data check.
    }
  }
  if (config.step === 1) {
    const visible = staticNoteCount > 0;
    return [{ attackId: 'anonymous_note_read', expected: '비로그인 화면에서 가상 메모를 확인',
      observed: visible ? '비로그인 요청에서 공개 가상 메모 확인 표시가 보임' : `비로그인 요청에서 확인 표시가 보이지 않음 (HTTP ${response.status})` }];
  }

  const apiResponse = await fetch(new URL('/api/notes', app), {
    redirect: 'error', signal: AbortSignal.timeout(10000),
  });
  let apiNoteCount;
  if (apiResponse.ok) {
    try {
      const data = await apiResponse.json();
      if (Array.isArray(data.notes)) apiNoteCount = data.notes.length;
    } catch {
      // Keep response bodies out of the self-check report.
    }
  }
  return [
    {
      attackId: 'anonymous_static_note_read',
      expected: '공개 정적 JSON에 가상 메모가 없음',
      observed: staticNoteCount === 0
        ? '정적 JSON에 메모 없음'
        : staticNoteCount === undefined
          ? `정적 JSON에서 메모 수 확인 불가 (HTTP ${response.status})`
          : `공개 정적 JSON에서 메모 ${staticNoteCount}건 노출`,
    },
    {
      attackId: 'anonymous_notes_api_read',
      expected: '공개 API는 인증 없이 호출 가능하므로 실제 자료를 넣지 않음',
      observed: apiNoteCount === undefined
        ? `공개 API 응답에서 메모 수 확인 불가 (HTTP ${apiResponse.status})`
        : `공개 API가 인증 없이 메모 ${apiNoteCount}건 응답; 본문 미기록`,
    },
  ];
}
