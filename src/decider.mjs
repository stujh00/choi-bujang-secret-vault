// ALEPH SDP 엔진이 검증해 전달한 요청의 기기 등록 여부만 사용합니다.
// 클라이언트가 직접 주장한 인증서·토큰·기기 정보는 신뢰하지 않습니다.
export const RULE_IDS = Object.freeze(['starter.deny', 'device_registered']);

export async function decide(request) {
  const base = {
    schema: 'aleph.decision.v1',
    requestId: request?.requestId,
  };
  // Only a strict boolean true counts as a registered device. Missing data fails closed.
  if (request?.deviceRegistered !== true) {
    return {
      ...base,
      decision: 'deny',
      reasonCode: 'device_not_registered',
      ruleIds: ['device_registered'],
    };
  }

  // The engine has already verified subjectId and deviceId. Do not invent
  // certificate validation, identity-to-device binding, or browser token checks.
  const hasVerifiedIdentityShape = request?.schema === 'aleph.decision.v1'
    && typeof request.subjectId === 'string' && request.subjectId.length > 0
    && typeof request.deviceId === 'string' && /^[0-9a-f]{16}$/.test(request.deviceId);
  const isNotesRead = request?.service === 'notes' && request.method === 'GET'
    && ((request.route === 'GET /notes' && request.path === '/notes')
      || (request.route === 'GET /notes/:id'
        && typeof request.path === 'string'
        && /^\/notes\/[^/?#]+$/.test(request.path)));

  if (hasVerifiedIdentityShape && isNotesRead) {
    return {
      ...base,
      decision: 'allow',
      reasonCode: 'approved',
      ruleIds: ['device_registered'],
    };
  }
  // Unrelated paths and methods are outside this stage's one new allow rule.
  // Retain the original starter.deny fallback for later policy stages.
  return {
    ...base,
    decision: 'deny',
    reasonCode: 'starter_not_ready',
    ruleIds: ['starter.deny'],
  };
}
