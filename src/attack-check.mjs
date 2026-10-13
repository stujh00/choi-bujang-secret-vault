// The student changes this check as each stage adds an attack to the same app.
// Never return tokens, private keys, real names, or note bodies.
const PRIVATE_VALUE_PATTERN = /-----BEGIN [A-Z ]*PRIVATE KEY-----|\bsb_(?:secret|publishable)_[A-Za-z0-9_-]{8,}\b|\bSUPABASE_SECRET_KEY\s*[:=]\s*["'][^"']+["']|\bBearer\s+[A-Za-z0-9._~+/-]{16,}|\beyJ[A-Za-z0-9_-]{12,}\.eyJ[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{8,}/iu;

async function fetchText(url, options = {}) {
  const response = await fetch(url, {
    redirect: 'error', signal: AbortSignal.timeout(10000), ...options,
  });
  return { response, text: await response.text() };
}

export async function runAttackChecks(config) {
  if (![1, 2, 3, 4, 5, 6, 7].includes(config.step)) throw new Error('이 단계의 공격 점검을 src/attack-check.mjs에 구현해 주세요.');
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
  const { response, text: staticDataText } = await fetchText(new URL('/data.json', app));
  let staticNoteCount;
  let staticData;
  if (response.ok) {
    try {
      const data = JSON.parse(staticDataText);
      staticData = data;
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

  if (config.step === 3) {
    const { response: apiResponse, text: apiResponseText } = await fetchText(new URL('/api/notes', app));

    let apiNoteCount;
    if (apiResponse.ok) {
      try {
        const data = JSON.parse(apiResponseText);
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
        attackId: 'anonymous_notes_api_auth',
        expected: '인증 없이 /api/notes 호출은 거부되어야 함',
        observed: apiResponse.status === 401 || apiResponse.status === 403
          ? `비로그인 API 호출이 ${apiResponse.status}로 거부됨`
          : apiNoteCount === undefined
            ? `비로그인 API 응답 상태 ${apiResponse.status}; 메모 수 확인 불가`
            : `비로그인 API가 메모 ${apiNoteCount}건 응답; 본문 미기록`,
      },
    ];
  }

  if (config.step === 5 || config.step === 6 || config.step === 7) {
    const { response: pageResponse, text: pageText } = await fetchText(new URL('/', app));
    const { response: identityResponse, text: identityText } = await fetchText(new URL('/aleph.json', app));
    const anonKey = pageText.match(/\bsb_publishable_[A-Za-z0-9_-]{8,}\b/u)?.[0];
    const staticHasPrivateValue = [staticDataText, pageText, identityText]
      .some(text => PRIVATE_VALUE_PATTERN.test(text));
    const staticHasSampleMarker = Object.hasOwn(staticData ?? {}, 'sampleMarker')
      || staticDataText.includes(config.sampleMarker);

    let originalApi;
    try {
      originalApi = new URL(config.originalApiUrl);
    } catch {
      throw new Error('aleph.config.json의 원본 자료 API HTTPS 주소를 확인해 주세요.');
    }
    if (originalApi.protocol !== 'https:' || originalApi.username || originalApi.password
        || originalApi.search || originalApi.hash || !originalApi.hostname.endsWith('.supabase.co')
        || originalApi.pathname !== '/rest/v1/vault_notes') {
      throw new Error('aleph.config.json의 원본 자료 API HTTPS 주소를 확인해 주세요.');
    }

    const anonHeaders = anonKey ? { apikey: anonKey } : {};
    const { response: sourceReadResponse, text: sourceReadText } = await fetchText(originalApi, {
      headers: anonHeaders,
    });
    let sourceReadCount;
    if (sourceReadResponse.ok) {
      try {
        const data = JSON.parse(sourceReadText);
        if (Array.isArray(data)) sourceReadCount = data.length;
      } catch {
        // Never include source data in the self-check report.
      }
    }

    const safeNoMatchId = '00000000-0000-0000-0000-000000000000';
    const updateUrl = new URL(originalApi);
    updateUrl.searchParams.set('id', `eq.${safeNoMatchId}`);
    const { response: sourceUpdateResponse } = await fetchText(updateUrl, {
      method: 'PATCH',
      headers: {
        ...anonHeaders,
        'Content-Type': 'application/json',
        Prefer: 'return=minimal',
      },
      body: JSON.stringify({ title: null }),
    });

    const staticAuditPassed = response.ok && staticNoteCount === 0 && !staticHasSampleMarker
      && pageResponse.ok && identityResponse.ok && !staticHasPrivateValue;
    const sourceReadObserved = sourceReadResponse.status === 401 || sourceReadResponse.status === 403
      ? `비인가 원본 API GET이 HTTP ${sourceReadResponse.status}로 거부됨${anonKey ? ' (anon 키 사용)' : ' (anon 키 미발견)'}`
      : sourceReadCount === undefined
        ? `비인가 원본 API GET 결과 HTTP ${sourceReadResponse.status}; 응답 자료는 기록하지 않음`
        : `비인가 원본 API GET이 메모 ${sourceReadCount}건을 반환; 본문 미기록`;
    const sourceUpdateObserved = sourceUpdateResponse.status === 401 || sourceUpdateResponse.status === 403
      ? `nil UUID 대상 비인가 PATCH가 HTTP ${sourceUpdateResponse.status}로 거부됨`
      : `nil UUID 대상 비인가 PATCH 결과 HTTP ${sourceUpdateResponse.status}; 권한 거부 여부는 본문 없이 판정할 수 없음`;

    const attempts = [
      {
        attackId: 'anonymous_static_data_secrecy',
        expected: '공개 정적 파일에 메모·SAMPLE_NOTE_1·비밀값이 없음',
        observed: staticAuditPassed
          ? 'data.json 메모 0건·표식 없음; index.html과 aleph.json에서 비밀값 패턴 없음'
          : `정적 노출 점검 실패 또는 불완전 (data.json HTTP ${response.status}, 메모 ${staticNoteCount ?? '확인 불가'}건, 표식 ${staticHasSampleMarker ? '있음' : '없음'}, index HTTP ${pageResponse.status}, aleph.json HTTP ${identityResponse.status}, 비밀값 패턴 ${staticHasPrivateValue ? '있음' : '없음'})`,
      },
      {
        attackId: 'anonymous_source_api_read',
        expected: 'anon 권한으로 원본 Supabase Data API 조회가 거부됨',
        observed: sourceReadObserved,
      },
      {
        attackId: 'anonymous_source_api_update',
        expected: 'anon 권한으로 원본 Supabase Data API 수정이 거부됨; 실제 행은 수정하지 않음',
        observed: sourceUpdateObserved,
      },
    ];
    if (config.step === 6 || config.step === 7) {
      const { decide, RULE_IDS } = await import('./decider.mjs');
      const { checkDecider } = await import('../scripts/decider-test.mjs');
      const localChecks = await checkDecider({ decide, ruleIds: RULE_IDS });
      const labels = [
        ['registered_device_read_local', '가상 등록 기기의 자료실 읽기는 허용'],
        ['unregistered_device_read_local', '가상 미등록 기기의 자료실 읽기는 device_not_registered로 거부'],
        ...(config.step === 7 ? [
          ['suspicious_step_up_local', '엔진 가상 복합 이상 사건은 추가 인증 전 step_up_required'],
          ['suspicious_reauthenticated_local', '새 로그인 시각을 엔진이 확인한 뒤 가상 요청을 재판정하여 허용'],
        ] : []),
      ];
      for (let i = 0; i < labels.length; i += 1) {
        const check = localChecks[i];
        attempts.push({
          attackId: labels[i][0],
          expected: labels[i][1],
          observed: check?.passed
            ? '로컬 판정기 가상 요청 연습 통과: ' + check.name
            : '로컬 판정기 가상 요청 연습 실패: ' + (check?.name || '확인 불가'),
        });
      }
    }
    return attempts;
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
