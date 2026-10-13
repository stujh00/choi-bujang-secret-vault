// Stage 9: the class engine supplies synthetic, identity-verified access events.
// This module emits a *proposal*, never revokes a token, device, or session.
// docs/DETECT_EVENTS.md defines only {at, method, identity:{sub}}.
// It does not carry a verified device ID or a trusted network signal.
const WINDOW_MS = 10 * 60 * 1000;
const THRESHOLD = 120;
const TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?Z$/;

function validEvent(event) {
  if (!event || typeof event !== 'object' || Array.isArray(event)
      || event.method !== 'GET'
      || typeof event.at !== 'string' || !TIMESTAMP.test(event.at)
      || !event.identity || typeof event.identity !== 'object'
      || typeof event.identity.sub !== 'string'
      || event.identity.sub.trim() !== event.identity.sub
      || event.identity.sub.length === 0
      || event.identity.sub.length > 128) return null;
  const timestamp = Date.parse(event.at);
  if (!Number.isFinite(timestamp)) return null;
  return { subject: event.identity.sub, timestamp };
}

export function detect(events) {
  if (!Array.isArray(events)) throw new TypeError('invalid_detection_events');

  const timestampsBySubject = new Map();
  for (const event of events) {
    const valid = validEvent(event);
    if (valid === null) continue;
    let timestamps = timestampsBySubject.get(valid.subject);
    if (!timestamps) {
      timestamps = [];
      timestampsBySubject.set(valid.subject, timestamps);
    }
    timestamps.push(valid.timestamp);
  }

  // Earliest crossing of 121 GETs inside a sliding 10-minute window wins.
  // Every account has its own counter; input ordering has no effect.
  let first = null;
  for (const [subject, timestamps] of timestampsBySubject) {
    timestamps.sort((a, b) => a - b);
    let start = 0;
    for (let end = 0; end < timestamps.length; end += 1) {
      while (timestamps[end] - timestamps[start] >= WINDOW_MS) start += 1;
      if (end - start + 1 > THRESHOLD) {
        const crossedAt = timestamps[end];
        if (first === null || crossedAt < first.crossedAt
            || (crossedAt === first.crossedAt && subject < first.subject)) {
          first = { subject, crossedAt };
        }
        break;
      }
    }
  }
  return first === null ? { action: 'observe' }
    : { action: 'propose_revocation', reasonCode: 'burst_read', subject: first.subject };
}
