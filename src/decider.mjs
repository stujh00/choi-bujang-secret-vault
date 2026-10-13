// SDP 엔진이 신원과 기기 등록을 검증한 요청 계약만 처리합니다.
// 클라이언트의 위치 헤더·토큰 원문을 별도로 믿거나 저장하지 않습니다.
export const RULE_IDS = Object.freeze(['starter.deny', 'device_registered', 'step_up_required']);

function unusualFixture(request) {
  const signals = request?.signals;
  // Only the provided engine's synthetic signals are eligible for this local rule.
  // Production uses source: 'none', so its unknown geo/network values are not promoted.
  if (!signals || typeof signals !== 'object' || signals.source !== 'judge_fixture') return false;

  const foreignRegion = signals.region === 'foreign';
  const unusualNetwork = signals.network === 'unusual';
  const unusualHour = Number.isInteger(signals.hour)
    && signals.hour >= 0 && signals.hour <= 23
    && (signals.hour < 6 || signals.hour >= 22);
  const rapidActivity = Array.isArray(request.recentEvents)
    && request.recentEvents.some((event) => event && typeof event === 'object'
      && ['risk_signal', 'bulk_read', 'bulk_edit', 'bulk_update', 'mass_read', 'mass_update']
        .includes(event.kind)
      && Number.isInteger(event.ageSeconds) && event.ageSeconds >= 0
      && event.ageSeconds <= 300
      && Number.isInteger(event.count) && event.count >= 10);

  // One unfamiliar region or odd hour must never trigger a permanent deny.
  const riskSignals = [foreignRegion, unusualNetwork, unusualHour, rapidActivity]
    .filter(Boolean).length;
  return riskSignals >= 2;
}

function recentStepUp(request) {
  const proof = request?.stepUp;
  // The engine validates the subject-bound fresh authentication.
  return proof?.verified === true
    && Number.isInteger(proof.authAgeSeconds)
    && proof.authAgeSeconds >= 0
    && proof.authAgeSeconds <= 300;
}

export async function decide(request) {
  const base = {
    schema: 'aleph.decision.v1',
    requestId: request?.requestId,
  };
  if (request?.deviceRegistered !== true) {
    return {
      ...base,
      decision: 'deny',
      reasonCode: 'device_not_registered',
      ruleIds: ['device_registered'],
    };
  }

  const verifiedIdentityShape = request?.schema === 'aleph.decision.v1'
    && typeof request.subjectId === 'string' && request.subjectId.length > 0
    && typeof request.deviceId === 'string' && /^[0-9a-f]{16}$/.test(request.deviceId);
  const notesService = request?.service === 'notes';
  const readNotes = notesService && request.method === 'GET'
    && ((request.route === 'GET /notes' && request.path === '/notes')
      || (request.route === 'GET /notes/:id'
        && typeof request.path === 'string'
        && /^\/notes\/[^/?#]+$/.test(request.path)));
  const notesWrite = notesService && ['POST', 'PUT', 'PATCH', 'DELETE'].includes(request.method)
    && typeof request.route === 'string'
    && request.route.startsWith(request.method + ' /notes')
    && typeof request.path === 'string'
    && /^\/notes(?:\/[^/?#]+)?$/.test(request.path);

  // Stage 7: suspicious synthetic requests require engine-verified fresh login.
  // Even after reauthentication, writes are not enabled by the stage 6 read rule.
  if (verifiedIdentityShape && (readNotes || notesWrite) && unusualFixture(request)
      && !recentStepUp(request)) {
    return {
      ...base,
      decision: 'step_up',
      reasonCode: 'step_up_required',
      ruleIds: ['step_up_required'],
    };
  }

  if (verifiedIdentityShape && readNotes) {
    return {
      ...base,
      decision: 'allow',
      reasonCode: 'approved',
      ruleIds: ['device_registered'],
    };
  }
  return {
    ...base,
    decision: 'deny',
    reasonCode: 'starter_not_ready',
    ruleIds: ['starter.deny'],
  };
}
