// 반 엔진이 검증한 사건만 전달받아 회수 제안만 만듭니다.
// 브라우저가 보낸 사용자 번호나 사건 원문은 저장·출력하지 않습니다.
export function detect(events) {
  if (!Array.isArray(events)) throw new TypeError('invalid_detection_events');

  const bySubject = new Map();
  for (const event of events) {
    if (!event || typeof event !== 'object' || Array.isArray(event)) continue;
    if (event.method !== 'GET') continue;

    const subject = event.identity?.sub;
    const timestamp = Date.parse(event.at);
    if (typeof subject !== 'string' || !subject.trim() || !Number.isFinite(timestamp)) continue;

    const subjectEvents = bySubject.get(subject) ?? [];
    subjectEvents.push(timestamp);
    bySubject.set(subject, subjectEvents);
  }

  for (const [subject, timestamps] of bySubject) {
    timestamps.sort((a, b) => a - b);
    let start = 0;
    for (let end = 0; end < timestamps.length; end += 1) {
      while (timestamps[end] - timestamps[start] > 10 * 60 * 1000) start += 1;
      if (end - start + 1 > 120) {
        return { action: 'propose_revocation', reasonCode: 'burst_read', subject };
      }
    }
  }

  return { action: 'observe' };
}
