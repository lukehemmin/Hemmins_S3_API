# 구현 로드맵

## 1. 목표

구현은 한 번에 모든 기능을 넣지 않고, 검증 가능한 단위로 끊어서 진행한다. 각 단계는 실제로 실행 가능하고 테스트 가능해야 한다.

## 2. 단계별 계획

### Phase 0. 프로젝트 부트스트랩

- `Go` 모듈 초기화
- 설정 로더 작성
- 설정 파일 + 환경변수 우선순위 모델 구현
- 정식 설정 스키마와 필드 검증 구현
- bootstrap 전용 환경변수 처리 구현
- 기본 HTTP 서버 구동
- 헬스체크 엔드포인트 추가
- 데이터 디렉터리 초기화 로직 추가
- 필수 경로 유효성 검증 추가
- 잘못된 설정에 대한 fail-fast 정책 구현

완료 기준:

- 서버가 기동된다.
- 설정 파일 또는 환경변수로 포트와 데이터 경로를 받을 수 있다.
- `/healthz`가 `200 OK`를 반환한다.
- 유효하지 않은 설정은 기동을 거부한다.

### Phase 1. 메타데이터와 로컬 스토리지

- `SQLite` 스키마 정의
- 버킷 메타데이터 CRUD
- 오브젝트 메타데이터 CRUD
- 파일 저장소 계층 구현
- 임시 파일과 원자적 이동 로직 구현
- `fsync`와 디렉터리 `fsync`를 포함한 쓰기 경계 구현
- startup recovery와 orphan quarantine 골격 구현

완료 기준:

- API 없이도 내부 서비스 레벨에서 버킷과 오브젝트를 저장/조회/삭제할 수 있다.
- 재시작 후 메타데이터가 유지된다.
- crash 이후 orphan 또는 손상 후보를 판별할 수 있다.

### Phase 2. S3 핵심 API

- `ListBuckets`
- `CreateBucket`
- `HeadBucket`
- `DeleteBucket`
- `PutObject`
- `GetObject`
- `HeadObject`
- `DeleteObject`
- `ListObjectsV2`
- XML 오류 응답 형식 구현
- 기본 헤더 호환 계약 구현

완료 기준:

- `aws s3 ls --endpoint-url ...`
- `aws s3 cp`
- `aws s3 rm`
- 주요 실패 케이스에서 `S3` 스타일 XML 오류를 반환한다.
- [s3-compatibility-matrix.md](./s3-compatibility-matrix.md)의 MVP 범위를 충족한다.

### Phase 3. 인증과 Presigned URL

- `SigV4` 검증 구현
- Access Key 저장 및 조회
- Presigned `GET/PUT` 지원
- 초기 bootstrap 흐름 구현
- 관리자 세션 만료와 `CSRF` 정책 구현
- Access Key 회전 흐름 구현

완료 기준:

- AWS SDK에서 커스텀 엔드포인트를 통해 인증 요청이 통과한다.
- Presigned URL로 업로드와 다운로드가 가능하다.
- bootstrap 완료 전 `setup-required` 상태가 명확히 동작한다.

### Phase 4. Multipart Upload

- 업로드 세션 생성
- 파트 업로드
- 파트 목록 조회
- 업로드 완료
- 업로드 중단
- 만료 파트 정리 작업

완료 기준:

- 대용량 파일 업로드가 정상 동작한다.
- 중단된 업로드의 임시 파일이 정리된다.

### Phase 5. 웹 UI

- 관리자 로그인
- 대시보드
- 버킷 목록/생성/삭제
- 오브젝트 탐색/업로드/삭제/다운로드
- 접근 키 발급/폐기
- 설정 조회 화면
- 경로 검증 및 재시작 필요 상태 표시

완료 기준:

- 브라우저에서 운영 기본 작업이 가능하다.
- UI와 API가 같은 서버에서 동작한다.
- 현재 유효 설정값과 저장 경로 상태를 웹 UI에서 확인할 수 있다.

### Phase 6. Docker와 운영성

- 멀티스테이지 `Dockerfile`
- `docker compose.yml`
- 환경변수 문서화
- 마운트 경로 예제 문서화
- 로그/메트릭/헬스체크 정리
- 백업/복원 절차 문서화
- 업그레이드와 롤백 절차 문서화

완료 기준:

- `docker compose up`으로 실행 가능하다.
- 볼륨 마운트 후 재기동에도 데이터가 유지된다.
- 단일 볼륨 구성과 경로 분리 구성을 모두 문서로 안내한다.
- 운영자가 백업, 복원, 업그레이드 절차를 문서만으로 수행할 수 있다.

### Phase 7. 호환성 검증과 하드닝

- AWS CLI 검증
- `boto3` 검증
- AWS SDK for Go 검증
- 재시작 복구 테스트
- 에러 응답 형식 정리
- 동시성 테스트
- compatibility fixture 확정
- schema migration과 restore smoke test 추가

완료 기준:

- 주요 SDK 시나리오가 자동화 테스트를 통과한다.
- 일반적인 실패 케이스에서 `S3` 스타일 오류 응답을 반환한다.
- 백업 복원본과 업그레이드 후 데이터 접근이 유지된다.

## 3. 테스트 전략

### 3.1 단위 테스트

- `SigV4` Canonical Request 계산
- 메타데이터 트랜잭션
- 스토리지 파일 이동
- Range 응답 처리

### 3.2 통합 테스트

- 버킷 생성부터 삭제까지 전체 흐름
- 오브젝트 업로드/다운로드/삭제
- Multipart Upload
- 재시작 후 데이터 유지
- bootstrap 이후 관리자 로그인
- 백업/복원 후 오브젝트 조회
- crash recovery 시나리오

### 3.3 호환성 테스트

- `aws s3api`
- `aws s3`
- `boto3`
- AWS SDK for Go v2
- `S3` XML 오류 응답 골든 테스트

## 4. 구현 우선순위

우선순위는 아래 순서가 맞다.

1. 데이터 무결성
2. `S3` 핵심 API 호환성
3. 인증
4. 대용량 업로드
5. 웹 UI
6. 운영 편의 기능

이 순서를 지켜야 초기에 "동작은 하지만 믿고 저장할 수 없는 시스템"이 되는 것을 피할 수 있다.

## 5. 첫 구현 스프린트 제안

가장 먼저 만들 작업 묶음은 아래가 적절하다.

- `Go` 프로젝트 초기화
- 설정 로더
- `SQLite` 연결
- 버킷/오브젝트 테이블 생성
- 로컬 파일 저장 인터페이스
- `PUT Object` / `GET Object` / `ListBuckets` 골격

이 스프린트가 끝나면 이후 작업은 실제 API와 UI를 쌓아 올리는 형태로 안정적으로 진행할 수 있다.
