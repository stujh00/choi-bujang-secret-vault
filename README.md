# BYTE BACK 방어전 시작 틀 R5

이 저장소는 1단계에서 학생 본인이 GitHub 저장소와 Vercel 배포를 만드는 출발점입니다. 포함된 메모 네 건은 가상 자료입니다. 실제 학생 자료, 토큰, 비밀키를 넣지 마세요.

## 학생이 하는 일: 세 걸음

1. GitHub 계정을 만듭니다.
2. 방어전 1단계 카드의 **Deploy** 버튼을 누릅니다. Vercel에 GitHub로 로그인하고, 새 저장소가 **본인 계정의 Public 저장소**인지 확인한 뒤 Deploy를 누릅니다.
3. 배포가 끝나면 화면에 나온 `https://…vercel.app` 주소를 방어전 1단계 카드에 붙여넣고 제출합니다. 저장소 주소나 설정 파일은 적지 않습니다.

배포가 끝나면 `/`에서 자료실을 볼 수 있습니다. 화면은 `/api/notes`를 호출하고, Vercel 서버 함수가 Supabase의 `vault_notes`에서 메모를 읽습니다. 공개 정적 `/data.json`에는 메모를 넣지 않습니다.

2단계에서는 Vercel 프로젝트의 **Settings > Environment Variables**에 `SUPABASE_URL`과 서버 전용 `SUPABASE_SECRET_KEY`를 설정해야 합니다. 비밀 키는 브라우저 코드, 정적 파일, 응답, 로그에 넣지 마세요. `/api/notes` 자체는 공개 주소이며 로그인이나 사용자별 권한 검사를 하지 않으므로, 누구나 이 주소를 호출해 응답의 네 가상 메모를 읽을 수 있습니다. Supabase 비밀 키를 사용하는 서버 함수의 RLS 우회는 이 공개 API를 보호하지 않습니다. 실제 개인 자료를 넣기 전에 인증과 접근 제어를 추가해야 합니다.

### 현재 파일 점검

다음 문장을 하나씩 정확히 검색합니다.

```text
실습용 가상 과제 기록
실습용 가상 포트폴리오 기록
실습용 가상 리추얼 기록
실습용 가상 행정 기록
```

배포 확인은 현재 **Production** 배포 주소의 `/data.json`을 열어 브라우저 찾기(Ctrl+F)로 위 문장을 검색합니다. 정적 JSON에서는 모두 검색되지 않아야 합니다. `/api/notes` 응답에는 네 문장이 나타나는 것이 현재 구현의 동작입니다. 이 API 주소는 공개되어 누구나 호출할 수 있으므로, 그 응답에서 문장이 보이는 것을 비공개 처리 성공으로 판정하지 마세요.

GitHub에서는 저장소의 현재 기본 브랜치에서 위 문장을 각각 검색합니다. 최신 파일 기준으로 `data.json`, `public/data.json`, `public/index.html`, `api/notes.js`에는 일치 항목이 없어야 합니다. `supabase/migrations/20261006000000_move_virtual_notes.sql`에는 테이블을 채우기 위한 문장이 의도적으로 있습니다. README의 이 검색 목록과 SQL seed 이외에 공개 정적 파일에서 일치 항목이 나오면 배포하지 말고 먼저 확인합니다.

이 점검은 현재 Production 배포와 기본 브랜치의 최신 파일만 확인합니다. 공개된 과거 Git 커밋이나 이전 Vercel 배포는 이 절차로 삭제되지 않습니다. 둘 중 하나라도 남아 있는 동안 과거 노출이 해소됐다고 쓰지 마세요.

## 3단계 저장점: 로그인 검증 + 개인 메모 CRUD

현재 구현은 다음 동작을 합니다.
- Supabase Auth JWT를 서버에서 확인하고, 로그인한 사용자의 세션만 허용합니다.
- `/api/notes` 목록은 로그인 사용자 메모만 반환합니다.
- `/api/notes` POST로 메모를 만들고, 메모 생성 시 서버 확인 사용자 ID를 `owner_id`로 저장합니다.
- `/api/notes/:id`에서 GET, PUT, DELETE로 단건 조회·수정·삭제를 수행합니다.
- 3단계 저장점 당시에는 단건 API 소유자 검사가 없었으며, 4단계 API에서는 검증된 사용자와 `owner_id`를 대조합니다.

### 4단계 API 소유권 검사와 RLS

현재 Vercel API는 서버 전용 `SUPABASE_SECRET_KEY`로 Supabase에 연결합니다. 이 권한은 RLS를 우회할 수 있으므로, RLS 정책만으로 공개 API의 사용자 간 접근을 막을 수 없습니다. 메모 API의 소유권 검사는 계속 유지해야 합니다. `supabase/step4-rls.sql`은 `vault_notes`의 최소 권한과 소유자별 RLS 정책을 적용하는 수동 학습 스크립트이며, Supabase SQL Editor에서 실행하기 전까지 DB에는 적용되지 않습니다.

4단계 저장점은 `aleph.config.json`의 `step: 4`로 API 소유권 검사와 RLS 설정을 추가했습니다. Vercel의 Git 저장소·커밋·배포 주소 검증과 `judgeIssuer`, `sampleMarker` 검증을 유지합니다.

### 5단계: 자료 요청을 서버 한곳으로 모으기

브라우저는 `/api/auth/login`, `/api/auth/logout`, `/api/auth/session` 서버 함수로 로그인·로그아웃·세션 확인을 요청합니다. 서버에서 Supabase Auth SDK를 사용하며 access/refresh token은 서명된 HttpOnly·Secure·SameSite 쿠키로만 전달합니다. 브라우저 JavaScript는 Supabase SDK, 공개 키, JWT를 사용하지 않습니다. 메모 조회·추가·수정·삭제는 Vercel의 `/api/notes`와 `/api/notes/:id`만 호출합니다. 쿠키 인증과 기존 외부 Bearer JWT 인증은 같은 JWT 검증기를 거치고, 서버는 확인한 사용자 ID와 `owner_id`를 비교합니다.

Vercel 프로젝트의 **Settings > Environment Variables**에 기존 `SUPABASE_URL`, `SUPABASE_SECRET_KEY`와 함께 서버 전용 `SUPABASE_PUBLISHABLE_KEY`를 설정합니다. 이 변수는 브라우저용 공개 설정으로 주입하지 않습니다. 인증 상태 변경 요청은 같은 출처 `Origin`만 허용하며 인증 응답은 저장되지 않습니다.

`aleph.config.json`의 `originalApiUrl`은 원본 Supabase REST 경로를 가리키며, `allowedRoutes`는 현재 메모 API 다섯 경로를 기록합니다. `supabase/step5-revoke-client-table-access.sql`은 `vault_notes`에서 `PUBLIC`, `anon`, `authenticated`의 테이블 권한을 회수합니다. 확인된 결과에서는 anon과 authenticated의 SELECT·INSERT·UPDATE·DELETE가 모두 `false`입니다.

Vercel API는 서버 전용 Supabase Secret Key를 사용하며 이 권한은 RLS를 우회할 수 있습니다. 그러므로 권한 회수와 RLS만으로 서버 API 접근을 보호한다고 가정하지 말고, 기존 JWT 검증과 `owner_id` 검사를 유지해야 합니다. 비밀 키는 브라우저 코드, 정적 파일, 응답, 로그에 넣지 않습니다.

5단계 배포는 `aleph.config.json`의 `step: 5`를 사용합니다. 공개 빌드와 배포 식별 검사는 1~5단계를 허용하며, 기존 Vercel 환경변수·`judgeIssuer`·`sampleMarker` 검증은 계속 적용됩니다. 로컬 정적 빌드 결과의 `/data.json`에는 메모나 `SAMPLE_NOTE_1` 표식이 포함되지 않습니다.

다시 실행하는 방법:
1. 로컬에서 정적 빌드: `npm run build -- --local`
2. 자동 시험: `npm run test`
3. 실제 API 확인: `npx vercel dev --listen 127.0.0.1:3000`
4. 브라우저에서 `http://127.0.0.1:3000` 접속
5. 로그인 후 메모를 생성·수정·삭제하고 로그아웃을 확인합니다.

## 시작 틀의 자동 처리

`vercel.json`은 정적 결과물 `public`을 배포합니다. 빌드 명령 `npm run build`는 Vercel이 제공하는 GitHub 저장소 소유자·이름, 커밋 SHA, 배포 URL을 검증하고 `public/aleph.json`을 생성합니다. 이 값이 없으면 빌드가 실패하므로, 성공한 것처럼 빈 주소를 내보내지 않습니다. `aleph.json`의 내용만으로 저장소 소유권이나 방어 성공을 인정하지 않습니다. 심판이 공개 저장소의 실제 커밋과 배포된 자료를 따로 대조해야 합니다.

`aleph.config.json`의 `repoUrl`과 `publicAppUrl`은 이전 제출 묶음 방식의 자리표시자입니다. 1단계에서는 학생이 편집하지 않습니다. 2단계 이후 코딩 도구가 필요한 설정과 보호 기능을 단계별로 작성합니다. `npm run bundle`과 `bundle-notes.json`도 1단계의 세 걸음에는 포함되지 않습니다.

로컬에서 가상 화면만 확인할 때는 `npm run build -- --local`을 사용합니다. 로컬 실행은 Vercel 배포나 심판 접수를 증명하지 않습니다. 저장소의 `src/attack-check.mjs`는 실제 배포가 된 뒤 `/data.json`을 비로그인으로 요청해 공개 가상 메모의 확인 표시를 읽습니다.

## 다음 단계의 코딩 도구에 전달할 규칙

[AGENTS.md](AGENTS.md)를 먼저 읽히고 한 번에 한 제작 단위만 요청하세요. 2단계부터는 자료 보호를 구현할 때 `public/data.json`을 복사하는 1단계 빌드 흐름도 함께 바꿔야 합니다. 3단계 이후의 로그인, 허용 경로, 5단계의 원본 API 주소, 6단계 이후 정책 규칙은 해당 단계 원고와 계약에 맞춰 추가합니다. 비밀번호·토큰·서버 전용 키·실제 학생 기록을 코드, Git, 제출 묶음에 넣지 않습니다.

`src/decider.mjs`와 `src/detect.mjs`의 로컬 시험은 반 엔진이나 운영 심판의 결과가 아닙니다. 1단계 이후 제출 묶음 계약 `aleph.defense.submission.v2`는 `scripts/bundle.mjs`에 남아 있으며, 코딩 도구가 해당 단계의 최신 배포 주소와 Git 원격을 맞춘 뒤 사용합니다.

## 보너스 XDR-03: 알려진 취약점 악용 탐지

- 수업용 경보 24건은 xdr/fixtures/known-cve.json에 있으며 수정하지 않았습니다.
- xdr/known-cve/read-alerts.mjs는 시각·출발 IP·계정·규칙 수준·설명만 추출하고 요청 페이로드를 출력하지 않습니다.
- xdr/known-cve/decide.mjs는 외부 의존 없이 JNDI 원격 조회 표기를 탐지하고, CVE 이름이나 점검 흔적만 있는 경보는 alert로 분류합니다.
- xdr/known-cve/respond.mjs는 차단 후보용 기한부 규칙과 xdr/alerts.log 기록을 위한 독립 모듈입니다. 기본 15분 만료이며 규칙은 기존 ZTNA src/decider.mjs에 실제로 연결되지 않습니다.
- 판정 실행: npm run xdr:run -- known-cve (xdr/known-cve/result.json 생성).
- 전체 프로젝트 테스트: npm run test. read-alerts.mjs의 요약 실행: node xdr/known-cve/read-alerts.mjs.

## 보너스 XDR-04: 지속성 공격 탐지 및 임시 격리 후보

- 수업용 Wazuh 경보는 `xdr/fixtures/persistence.json` 총 24건입니다. 원본 경보는 변경하지 않습니다.
- `xdr/persistence/read-alerts.mjs`는 시각·출발 주소·계정·수준·설명만 읽고, 경보 원문이나 경로에 있을 수 있는 비밀값을 콘솔에 출력하지 않습니다.
- `patterns.json`은 MITRE T1543·T1053과 서비스 등록·예약 작업·시작 프로그램 단서를 정리합니다.
- 오프라인 독립 모듈 `decide.mjs`는 명확한 서비스·작업·시작 프로그램 지속성 공격만 block, 증거 부족 경보는 alert, 기존 정상 이벤트는 record로 반환합니다. 경보 번호별 하드코딩을 사용하지 않습니다.
- `respond.mjs`는 후보 차단 경보의 **agent.name**을 기준으로 임시 격리 후보 규칙을 생성하고, 중복 경보를 병합하며 기본 15분 후 만료합니다. `xdr/alerts.log`에는 원본 실행 파일 경로나 원본 경보를 기록하지 않습니다.
- **주의:** Wazuh agent.name은 운영 엔진이 확인한 deviceId가 아닙니다. 현재 `src/decider.mjs`는 `starter.deny` 상태이며, ZTNA 접근 계약과 이 후보 규칙을 연결하는 검증된 기기 매핑은 없습니다. 실제 기기 격리·정상 사용자 접근 허용·운영 방화벽 차단은 구현하거나 주장하지 않습니다.
- 경보 요약 실행: `node xdr/persistence/read-alerts.mjs`
- 판정 시험: `npm run xdr:run -- persistence` → `xdr/persistence/result.json` 생성
- 전체 프로젝트 회귀 시험: `npm run test` (별도 Node.js 실행 환경에서 확인해야 합니다).

## 보너스 XDR-05: 권한 가로채기 징후 및 세션 회수 후보

- Wazuh 형식의 수업용 `xdr/fixtures/privilege.json` 26건은 변경하지 않습니다.
- `xdr/privilege/read-alerts.mjs`는 시각·출발 주소·계정·규칙 수준·설명만 읽고 경보 원문 또는 비밀값은 표시하지 않습니다.
- `patterns.json`에는 MITRE T1068(권한 상승 악용)·T1078(정상 계정 도용)을 참고하여 비정상 관리자 그룹 추가, 승격 직후 명령 사용, 대량 변경·재부여와 모호한 사건을 구별합니다.
- `decide.mjs`는 외부 패키지와 파일 접근 없이 `decide(alert)`를 실행합니다. 명확한 권한 상승·가로채기 징후는 block, 모호하면 alert, 일반 로그인·조회는 record입니다.
- `respond.mjs`는 유효한 block에 대해 계정 이름 기준의 **세션 회수 후보 규칙**을 독립 저장합니다. 규칙은 기본 15분 후 만료되며 동일 계정의 경보 근거를 병합합니다. `xdr/alerts.log`에는 경보 ID, 행동, 확신도, 사유와 처리 결과만 기록합니다.
- **범위 제한:** Wazuh `data.srcuser`는 검증된 ZTNA `subjectId`가 아니므로 현재 `src/decider.mjs`에 실제 연결되지 않았습니다. Supabase 로그아웃이나 운영 사용자의 세션 무효화는 수행하지 않습니다.
- 경보 수 확인: `node xdr/privilege/read-alerts.mjs`.
- 판정 결과 생성: `npm run xdr:run -- privilege` → `xdr/privilege/result.json`.
- 기존 전체 회귀 테스트: `npm run test` (Node.js 저장소 환경에서 별도 실행해야 합니다).

## 보너스 XDR-06: 자료 반출 및 외부 목적지 차단 후보

- 원본 경보 `xdr/fixtures/exfiltration.json` 30건은 변경하지 않았습니다.
- `xdr/exfiltration/read-alerts.mjs`는 시각·출발 주소·계정·규칙 수준·설명만 추출하고 목적지 주소나 전송 데이터 원문을 출력하지 않습니다.
- `patterns.json`과 독립형 `decide.mjs`는 MITRE T1041·T1048을 참고하여 낯선 목적지의 대용량 전송, 업무 외 시간 압축 파일 반출, 반복·우회 경로 전송을 종합적으로 판정합니다.
- 제공된 경보 30건을 로컬 판정 함수로 검사하면 block 10건, alert 10건, record 10건입니다. 전송량이 크거나 MITRE 태그가 있다는 사실만으로 자동 차단하지 않습니다.
- `respond.mjs`는 block 판정의 목적지 IP별 임시 deny 후보 규칙을 만들어 기본 15분 뒤 만료시키고, 같은 IP에 대한 여러 근거 경보를 병합합니다. 알림은 `xdr/alerts.log`에 ID·행동·확신도·근거·처리 결과만 기록합니다.
- **운영 범위:** `xdr-run.mjs`는 `decide.mjs`만 호출합니다. `respond.mjs`는 격리된 실습용 저장소에서 독립 검증했으며, 실제 방화벽·ZTNA 정책에 연결되어 있지 않습니다. `src/decider.mjs`를 수정하거나 실자료 전송을 차단하지 않습니다.
- 경보 추출 확인: `node xdr/exfiltration/read-alerts.mjs`.
- 판정 결과 재생성: `npm run xdr:run -- exfiltration` → `xdr/exfiltration/result.json`.
- 전체 회귀 테스트: `npm run test` (Node.js 저장소 환경에서 별도 실행 필요).

## 6단계 저장점: 등록 기기에서만 자료실 읽기

- **현재 진행 단계는 6단계입니다.** 위쪽 1~2단계 설명과 과거 3~5단계 저장점 기록은 해당 당시의 이력을 설명하며, 현재 공개 API가 비로그인으로 메모를 제공한다는 뜻이 아닙니다. 5단계 인증·메모 소유권 보호·서버 API 경유 기능은 그대로 유지합니다.
- `docs/DECIDER_REQUEST.md`의 SDP 엔진이 검증한 `subjectId`는 사용자 가명 ID, `deviceId`는 검증된 기기 ID이며, 기기 등록 여부는 `deviceRegistered`의 **엄격한 Boolean true**로 판단합니다. 인증서·CA·개인키를 별도로 생성하거나 저장하지 않습니다.
- `src/decider.mjs`는 등록된 기기의 `notes` 서비스 **GET 읽기 요청**(`GET /notes`, `GET /notes/:id`)만 `allow / approved / device_registered`로 응답합니다. `deviceRegistered`가 false이거나 없으면 `deny / device_not_registered / device_registered`로 거부합니다. 다른 서비스·수정 요청은 기존 `starter.deny`가 거부합니다.
- 6단계는 운영 엔진의 기기 검증 결과에 대한 판정기 규칙입니다. 인증서가 없는 mTLS 연결, 다른 사용자 토큰 혼합에 대한 검사·차단은 엔진의 선행 인증 기능이 담당합니다. 로컬 판정기 한 파일만으로 실제 인증서 검증이나 사용자-기기 결합 방어를 입증하지 않습니다.
- `aleph.config.json`의 `step`을 6으로 변경하고 공개 빌드·배포 메타데이터 검사에서도 6단계를 허용합니다. 기존 배포 주소, 신원 발급자, `allowedRoutes`, `originalApiUrl`, `judgeIssuer`는 변경하지 않았습니다.
- **로컬 가상 요청 검사:** `npm run decider:test` → `통과 · 등록 기기의 정상 요청` 및 `통과 · 미등록 기기의 가상 요청`. 이것은 심판 결과나 실제 기기 등록 성공의 증거가 아닙니다.
- **정적 빌드 및 회귀 검사:** `npm run build -- --local`, `npm run test`.
- **제출 점검:** 커밋 후 로컬의 `bundle-notes.json`(Git에 올리지 않음)에 단계 설명을 준비하고, 깨끗한 작업 트리에서 `npm run bundle`을 실행합니다. 결과 `artifacts/submission.json`은 Git에 커밋하지 않습니다. 6단계 직접 점검에는 기존 5단계 정적 노출·원본 API 차단 점검과 등록/미등록 기기 가상 판정 2건을 구분해 남깁니다.

## 7단계 저장점: 평소와 다른 가상 접속은 추가 확인

- **현재 진행 단계는 7단계**입니다. 1~6단계 저장점과 여섯 개 보너스 XDR 모듈은 보존했습니다. 기존 웹 자료실의 서버 인증·소유자 권한·RLS·원본 API 회수 설정을 변경하지 않았습니다.
- `src/decider.mjs`의 기존 `device_registered`는 유지하고 `step_up_required` 규칙을 추가했습니다. 미등록·등록 정보 누락 기기는 이전처럼 `deny / device_not_registered`로 우선 거부합니다.
- 엔진이 검증해 전달한 `signals.source === 'judge_fixture'`의 **가상 사건**에서 낯선 지역·네트워크·비정상 시각·최근 5분 이내 다량 활동(10회 이상) 중 2개 이상 겹치면 `step_up / step_up_required`로 추가 본인 확인을 요청합니다. 지역 하나만으로 거부하지 않습니다.
- 실제 접속의 `signals.source: 'none'`과 클라이언트 임의 헤더는 신뢰할 수 있는 위치 증거로 승격하지 않습니다. 누락된 지역·시각·네트워크·행동을 임의의 정상 값으로 보충하지 않습니다.
- SDP 엔진이 동일 주체의 최근 추가 인증 결과로 제공한 `stepUp.verified === true`와 `authAgeSeconds` 0~300초만 이 규칙의 재인증 완료로 판단합니다. 검증된 가상 복합 사건은 미완료 시 `step_up`, 완료 시 자료실 **GET 읽기**에 한해 `allow / approved`가 됩니다. 위험한 쓰기 요청은 재확인을 마쳐도 기존 `starter.deny`에서 허용하지 않습니다.
- **실제 재로그인 완료 및 운영 경로 차단은 미실행입니다.** SDP 반 엔진의 신원 결합·재인증 검증을 모방하거나 실제 사용자 세션·토큰을 다루지 않습니다. 로컬 검사는 계약에 맞춘 가상 요청 연습입니다.
- 로컬 가상 판정: `npm run decider:test` → 등록·미등록 기기와 복합 이상 접속·재확인 후 접속 4건 통과. `npm run fixture:7` → 정상 `allow`, 복합 이상 `step_up`.
- 기존 회귀·정적 빌드: `npm run test`, `npm run build -- --local`. 커밋 후 생성하는 `npm run bundle`은 공개 정적 검사·원본 API 비인가 검사와 로컬 가상 판정 4건을 구별해 결과만 기록하고 비밀값은 기록하지 않습니다.

## 8단계 저장점: 자원 구역별 서버 권한 검사

- 현재 단계는 **8단계**입니다. 기존 1~7단계와 보너스 XDR 1~6의 코드는 보존합니다.
- `src/resource-zones.mjs`에서 개인 메모는 `/api/notes/:id`의 UUID, 강사 공지는 `/api/announcements/:id`의 예약 UUID `00000000-0000-4000-8000-0000000000f0`로 명확히 구분합니다. `export` 등 기능 별칭·중첩 경로·쿼리 기반 ID 선택은 거부합니다. UI 메뉴와 메모 본문은 수정하지 않습니다.
- 기존 Supabase `vault_notes`의 개인 메모를 전부 보존합니다. `/api/notes` 목록은 서버 검증 사용자 ID를 `owner_id`로 조회하고, 결과 행의 `owner_id`도 재확인합니다. 단건 GET·PUT·DELETE도 ID와 DB의 `owner_id`를 함께 적용합니다. 공지 UUID는 개인 메모 목록·단건 API에서 제외합니다.
- 공지는 기존 테이블의 **예약 UUID 하나**에만 별도 보관합니다. 인증된 학생은 `/api/announcements`에서 게시된 공지를 조회할 수 있으나, 게시·수정·삭제는 서버에서 확인한 Supabase Auth Admin `app_metadata.vault_role === 'instructor'`인 사용자에게만 허용됩니다. 브라우저 입력, 요청 본문의 role, 변경 가능한 `user_metadata`는 무시합니다. 강사 역할이 지정되지 않았다면 쓰기는 기본 거부됩니다.
- **강사 권한이나 공지를 자동으로 생성하지 않았습니다.** 필요시 운영자가 Supabase의 관리자 권한을 통해 실제 강사 사용자의 `app_metadata.vault_role`을 `instructor`로 지정해야 합니다. 이름·이메일·토큰은 Git에 기록하지 않습니다. 공지 게시 API는 그 후 정상 동작합니다.
- SDP 판정기 요청 계약에는 실제 메모의 `owner_id`나 강사 역할이 없습니다. 따라서 `src/decider.mjs`는 자원 경로를 엄격히 판단하되 소유권 확인이 불가능한 쓰기 권한을 새로 허용하지 않습니다. 최종 데이터 구역은 서버 API와 DB가 검증합니다. 학생 계정의 강사 공지 수정은 거부됩니다.
- **검증:** `npm run decider:test`, `npm run fixture:7`, `npm run test`, `npm run build -- --local`. `npm run bundle`의 교차 계정 실서비스 검증은 운영 계정 비밀값 없이 실행하지 않았으므로 `미실행`으로 기록합니다.
