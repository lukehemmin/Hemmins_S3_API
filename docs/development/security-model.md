# 보안 모델

## 1. 목적

이 문서는 초기 부트스트랩, 비밀값 저장, 키 회전, UI 세션, 감사 로그, 프록시 신뢰 경계를 정의한다.

## 2. 보안 경계

이 시스템의 핵심 보안 경계는 아래와 같다.

- 관리자 웹 UI
- `S3` API 엔드포인트
- 설정 파일
- 메타데이터 DB
- 오브젝트 데이터 디렉터리
- 리버스 프록시 또는 TLS 종료 지점

기본 가정은 아래다.

- 관리자 권한은 고신뢰 운영자만 가진다.
- 디스크와 컨테이너 호스트 접근 권한이 있으면 시스템 전체를 장악할 수 있다.
- `auth.master_key` 유출은 Access Key 비밀값 유출과 동일급 사고다.

## 3. 초기 부트스트랩

### 3.1 기본 원칙

- 기본 공유 자격 증명은 제공하지 않는다.
- 빈 메타데이터 DB에서만 초기 부트스트랩을 허용한다.
- 부트스트랩 완료 전에는 서비스가 `setup-required` 상태가 된다.

### 3.2 부트스트랩 경로

MVP에서는 두 경로를 허용한다.

1. Headless bootstrap
2. UI bootstrap wizard

Headless bootstrap:

- `HEMMINS_BOOTSTRAP_ADMIN_USERNAME`
- `HEMMINS_BOOTSTRAP_ADMIN_PASSWORD`
- `HEMMINS_BOOTSTRAP_ROOT_ACCESS_KEY`
- `HEMMINS_BOOTSTRAP_ROOT_SECRET_KEY`

UI bootstrap wizard:

- 메타데이터 DB가 비어 있고 bootstrap 환경변수가 없을 때만 노출
- 이 시점에는 일반 관리자 로그인 화면 대신 설치 화면만 노출
- 설치 완료 전까지 `S3` API는 `503 ServiceUnavailable`를 반환
- `/readyz`는 실패 상태를 유지

## 4. 비밀값 저장 정책

### 4.1 관리자 비밀번호

- 평문 저장 금지
- 적응형 password hash로 저장
- 해시값은 다시 평문으로 복구할 수 없어야 한다

### 4.2 API Access Key 비밀값

- 메타데이터 DB에 암호화 저장
- 암호화 키는 `auth.master_key`
- 생성 직후를 제외하고는 UI/API에서 평문 재표시 금지

### 4.3 설정과 로그

- 설정 화면은 secret 값을 항상 마스킹한다.
- 로그에 secret, session cookie, Authorization header 전체값을 남기지 않는다.
- `config.yaml` 예시에는 실제 secret를 넣지 않는다.

## 5. 키 수명주기와 회전

### 5.1 Access Key 회전

권장 절차는 아래와 같다.

1. 새 키 발급
2. 클라이언트 전환
3. 이전 키 비활성화
4. 일정 유예 후 삭제

정책:

- 최소 1개의 활성 root-scoped key는 유지해야 한다.
- 비활성화된 키는 즉시 새 요청 인증에 사용될 수 없어야 한다.
- 키 생성/비활성화/삭제는 모두 감사 로그 대상이다.

### 5.2 관리자 비밀번호 회전

- 관리자 비밀번호 변경 시 기존 세션은 무효화한다.
- 변경 작업은 재인증을 요구한다.

### 5.3 마스터 키 회전

마스터 키 회전은 온라인 즉시 반영 대상이 아니다.

- 유지보수 모드에서 수행한다.
- 저장된 모든 Access Key secret를 재암호화해야 한다.
- 회전 실패 시 이전 백업으로 복구할 수 있어야 한다.
- 기존 마스터 키를 잃어버리면 저장된 API secret는 복구할 수 없다.

## 6. UI 세션 보안 정책

- 세션 쿠키는 `HttpOnly`
- HTTPS 환경에서는 `Secure`
- `SameSite=Lax`
- 상태 변경 요청은 `CSRF` 방어 적용
- 절대 만료와 유휴 만료를 모두 적용
- 로그아웃 시 세션 즉시 무효화

권장 기본값:

- 절대 만료 `12h`
- 유휴 만료 `30m`

## 7. TLS와 프록시 신뢰 경계

- 프로덕션에서는 TLS 사용을 전제한다.
- TLS 종료를 리버스 프록시에서 할 수 있다.
- `server.trust_proxy_headers` 기본값은 `false`
- 신뢰 가능한 프록시 뒤에서만 `X-Forwarded-*`를 신뢰한다.
- public endpoint가 `https://`이면 UI는 `Secure` 쿠키를 강제해야 한다.

## 8. 감사 로그 정책

최소한 아래 이벤트를 감사 로그로 남긴다.

- 관리자 로그인 성공/실패
- 관리자 로그아웃
- 비밀번호 변경
- Access Key 생성/비활성화/삭제
- 설정 변경 시도 및 성공/실패
- 저장 경로 변경 시도
- bootstrap 완료
- 권한 오류와 서명 검증 실패

감사 로그는 일반 access log와 분리 가능해야 한다.

## 9. 장애와 복구 시 보안 정책

- `auth.master_key` 유실은 보안 사고이자 운영 장애로 간주한다.
- 관리자 계정 분실은 UI self-service가 아니라 유지보수 절차로 복구한다.
- bootstrap 환경변수는 운영 중 상시 주입을 권장하지 않는다.
- 백업에는 메타데이터 DB, 설정 파일, 오브젝트 데이터뿐 아니라 마스터 키 보관 전략도 포함돼야 한다.

## 10. 구현 시 체크포인트

- no default credentials
- no secret re-display
- key rotation without downtime for API clients
- session invalidation on privileged changes
- audit coverage for all admin-sensitive actions

이 문서는 [configuration-model.md](./configuration-model.md), [operations-runbook.md](./operations-runbook.md)와 함께 유지한다.
