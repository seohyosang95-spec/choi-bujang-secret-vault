// The student changes this check as each stage adds an attack to the same app.
// Never return tokens, private keys, real names, or note bodies.
export async function runAttackChecks(config) {
  if (![1, 2, 3, 4, 5].includes(config.step)) {
    throw new Error('이 단계의 공격 점검을 src/attack-check.mjs에 구현해 주세요.');
  }
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

  const staticResponse = await fetch(new URL('/data.json', app), {
    redirect: 'error', signal: AbortSignal.timeout(10000),
  });
  if (config.step === 1) {
    if (typeof config.sampleMarker !== 'string' || !config.sampleMarker) {
      throw new Error('가상 메모의 확인 표시를 넣어 주세요.');
    }
    let visible = false;
    if (staticResponse.ok) {
      try {
        const data = await staticResponse.json();
        visible = data?.sampleMarker === config.sampleMarker && Array.isArray(data.notes)
          && data.notes.length > 0;
      } catch {
        // A non-JSON response is a failed check, not a successful deployment.
      }
    }
    return [{ attackId: 'anonymous_note_read', expected: '비로그인 화면에서 가상 메모를 확인',
      observed: visible ? '비로그인 요청에서 공개 가상 메모 확인 표시가 보임' : `비로그인 요청에서 확인 표시가 보이지 않음 (HTTP ${staticResponse.status})` }];
  }

  let hidden = staticResponse.status === 404;
  if (staticResponse.ok) {
    try {
      const data = await staticResponse.json();
      hidden = Array.isArray(data?.notes) && data.notes.length === 0;
    } catch {
      // A non-JSON success response does not prove that the public notes are gone.
    }
  }

  const apiResponse = await fetch(new URL('/api/notes', app), {
    redirect: 'error', signal: AbortSignal.timeout(10000),
  });
  let apiVisible = false;
  let jsonDenied = false;
  try {
    const data = await apiResponse.json();
    apiVisible = Array.isArray(data) ? data.length > 0
      : Array.isArray(data?.notes) && data.notes.length > 0;
    jsonDenied = [401, 403].includes(apiResponse.status)
      && typeof data?.error === 'string' && data.error.length > 0;
  } catch {
    // Only a JSON error proves the stage-three unauthenticated rejection contract.
  }

  if (config.step === 2) {
    return [
      { attackId: 'anonymous_note_read_static', expected: '비로그인 요청에서 정적 가상 메모를 읽을 수 없음',
        observed: hidden ? '공개 data.json에 가상 메모가 없음' : `공개 data.json에 자료가 남아 있거나 응답을 확인할 수 없음 (HTTP ${staticResponse.status})` },
      { attackId: 'anonymous_note_read_api', expected: '공개 API가 비로그인 요청에 가상 메모를 반환하는 남은 약점 확인',
        observed: apiVisible ? '비로그인 요청에서 공개 API의 가상 메모가 보임' : `비로그인 요청에서 공개 API 메모를 확인하지 못함 (HTTP ${apiResponse.status})` },
    ];
  }

  return [
    { attackId: 'anonymous_note_read_static', expected: '비로그인 요청에서 정적 가상 메모를 읽을 수 없음',
      observed: hidden ? '공개 data.json에 가상 메모가 없음' : `공개 data.json에 자료가 남아 있거나 응답을 확인할 수 없음 (HTTP ${staticResponse.status})` },
    { attackId: 'anonymous_note_read_api', expected: '비로그인 자료 API가 JSON 오류와 함께 401 또는 403으로 거부됨',
      observed: jsonDenied ? `비로그인 자료 API가 JSON 오류로 거부됨 (HTTP ${apiResponse.status})` : `비로그인 자료 API 거부 계약을 확인하지 못함 (HTTP ${apiResponse.status})` },
  ];
}
