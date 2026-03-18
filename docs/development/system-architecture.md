# 시스템 아키텍처

## 1. 아키텍처 개요

권장 구조는 "하나의 서버 프로세스 + 하나의 메타데이터 DB + 로컬 파일시스템 스토리지"다.

```text
Client / SDK / CLI
        |
        v
+-----------------------+
| HTTP Server           |
| - S3 API Router       |
| - UI Router           |
| - Health / Metrics    |
+-----------------------+
        |
        v
+-----------------------+
| Service Layer         |
| - SigV4 Auth          |
| - Bucket Service      |
| - Object Service      |
| - Multipart Service   |
| - Access Key Service  |
+-----------------------+
        |
   +----+----+
   |         |
   v         v
+------+   +------------------+
|SQLite|   | Local Filesystem |
|Meta  |   | Blob Storage     |
+------+   +------------------+
```

## 2. 핵심 설계 결정

### 2.1 메타데이터는 SQLite

이유는 명확하다.

- 단일 노드 요구사항에 충분하다.
- 트랜잭션을 제공한다.
- 운영 부담이 낮다.
- 별도 외부 DB가 필요 없다.

권장 설정은 아래와 같다.

- `WAL` 모드
- `busy_timeout` 설정
- 외래 키 활성화
- 주기적 `VACUUM` 또는 유지보수 작업

### 2.2 오브젝트 데이터는 로컬 파일시스템

오브젝트 본문은 DB에 넣지 않고 파일로 저장한다.

- 큰 파일 스트리밍에 유리하다.
- 운영자가 디스크 사용량을 직관적으로 이해할 수 있다.
- 백업 전략을 단순화할 수 있다.

### 2.3 같은 바이너리에서 UI를 서빙

- 배포 단위를 줄인다.
- CORS와 인증 구성이 단순해진다.
- Docker 이미지가 하나면 충분하다.

### 2.4 설정은 파일 + 환경변수 조합

- 기본 운영 설정은 `config.yaml`에서 읽는다.
- 민감정보와 배포 환경별 차이는 환경변수로 오버라이드한다.
- `.env`는 애플리케이션 설정 포맷이라기보다 로컬 개발과 `docker compose` 보조 수단으로 간주한다.

권장 우선순위는 아래와 같다.

1. 환경변수
2. 설정 파일
3. 기본값

정식 스키마와 병합 규칙은 [configuration-model.md](./configuration-model.md)를 따른다.

## 3. 디렉터리 레이아웃 제안

런타임 데이터 구조는 아래 형태를 권장한다.

```text
/data
  /meta
    metadata.db
  /objects
    /ab
      /cd
        <object_id>.blob
  /multipart
    /<upload_id>
      part-00001
      part-00002
  /tmp
  /logs
```

설명:

- `/meta/metadata.db`: `SQLite` 메타데이터 저장소
- `/objects`: 실제 오브젝트 파일
- `/multipart`: 완료 전 파트 임시 저장소
- `/tmp`: 요청 처리 중 임시 파일

`object_id`는 UUID 또는 내부 고유 ID를 사용하고, 파일 경로는 키 이름과 분리한다. 키 이름을 그대로 파일 경로로 쓰지 않는 이유는 경로 이스케이프, 긴 파일명, 특수문자 처리 복잡도를 줄이기 위해서다.

중요한 제약:

- `temp_root`와 `object_root`는 같은 파일시스템이어야 한다.
- 그렇지 않으면 원자적 `rename` 기반 쓰기 경계를 보장할 수 없다.

## 3.1 설정 모델 제안

경로와 서버 설정은 아래 형태의 구조체로 관리하는 것이 적절하다.

```text
Config
  Server
  Paths
  Auth
  UI
  Logging
  GC
```

초기 버전에서 특히 중요한 항목은 아래다.

- `paths.meta_db`
- `paths.object_root`
- `paths.multipart_root`
- `paths.temp_root`
- `server.public_endpoint`

## 3.2 변경 가능성 분류

설정은 두 종류로 분리하는 편이 좋다.

- 재시작 없이 바꿀 수 있는 설정
- 재시작이 필요한 설정

재시작이 필요한 대표 항목:

- 저장 경로
- 메타데이터 DB 경로
- Listen Address
- 마스터 키

웹 UI는 이 구분을 반드시 보여줘야 한다.

## 4. 메타데이터 모델 제안

### 4.1 buckets

- `id`
- `name`
- `created_at`

### 4.2 objects

- `id`
- `bucket_id`
- `object_key`
- `size`
- `etag`
- `content_type`
- `storage_path`
- `last_modified`
- `metadata_json`
- `checksum_sha256`

`bucket_id + object_key`는 유니크 키로 둔다.

### 4.3 multipart_uploads

- `id`
- `bucket_id`
- `object_key`
- `initiated_at`
- `metadata_json`

### 4.4 multipart_parts

- `upload_id`
- `part_number`
- `etag`
- `size`
- `staging_path`

### 4.5 access_keys

- `id`
- `access_key`
- `secret_ciphertext`
- `status`
- `description`
- `created_at`
- `last_used_at`

중요한 점은 `SigV4` 검증을 위해 비밀값의 원문이 필요하다는 것이다. 따라서 단순 해시 저장으로는 부족하다. 초기 버전은 인스턴스 마스터 키로 암호화된 형태로 저장하는 것이 현실적이다.

### 4.6 ui_users

- `id`
- `username`
- `password_hash`
- `role`
- `created_at`

## 5. 요청 처리 흐름

### 5.1 PUT Object

1. 요청 헤더와 `SigV4` 서명을 검증한다.
2. 대상 버킷과 키 유효성을 확인한다.
3. 요청 본문을 임시 파일로 스트리밍 저장한다.
4. 업로드 중 체크섬과 `ETag` 계산에 필요한 값을 함께 수집한다.
5. 임시 파일을 `fsync`한다.
6. 임시 파일을 최종 오브젝트 경로로 원자적 이동한다.
7. 대상 디렉터리를 `fsync`한다.
8. `SQLite` 트랜잭션으로 메타데이터를 갱신하고 커밋한다.
9. 성공 응답을 반환한다.

핵심은 "파일 영속화 후 메타데이터 커밋" 순서를 유지하는 것이다. 이 경계를 넘기기 전에는 성공 응답을 반환하지 않는다.

### 5.2 GET Object

1. 인증을 검증한다. Presigned URL이면 쿼리 서명을 검증한다.
2. 메타데이터를 조회한다.
3. Range 헤더를 파싱한다.
4. 파일을 스트리밍 응답한다.

### 5.3 Multipart Upload

1. 업로드 세션 생성
2. 각 파트는 `/multipart/<upload_id>/part-xxxxx`에 저장
3. 완료 요청 시 파트 순서와 `ETag`를 검증
4. 파트를 순서대로 병합해 최종 임시 오브젝트 생성
5. 최종 임시 오브젝트를 `fsync` 후 최종 경로로 이동
6. 메타데이터 커밋 후 임시 파트 정리

Multipart와 `ETag` 의미론은 [s3-compatibility-matrix.md](./s3-compatibility-matrix.md)를 따른다.

## 6. 일관성과 복구 전략

### 6.1 쓰기 경계

MVP에서는 아래 규칙을 지킨다.

- 파일은 먼저 디스크에 저장
- 최종 경로 이동 전 임시 파일을 `fsync`
- 이동 후 대상 디렉터리를 `fsync`
- 이후 메타데이터 트랜잭션 커밋
- 커밋 전 실패 파일은 고아 파일로 간주하고 정리 가능

추가 계약:

- `SQLite`는 `WAL` 모드와 `synchronous=FULL`을 기본으로 한다.
- `temp_root`와 `object_root`가 다른 파일시스템이면 기동을 거부한다.
- 응답 성공 시점은 "파일 경로 반영 + 디렉터리 fsync + DB commit" 이후다.

### 6.2 시작 시 복구

프로세스 시작 시 아래 작업을 수행한다.

- 오래된 `/tmp` 파일 정리
- 만료된 Multipart 업로드 정리
- 메타데이터에 없는 고아 파일 정리 후보 스캔

즉시 삭제보다 "후보 기록 후 정리" 방식이 더 안전하다.

최소 복구 규칙:

- 임시 파일만 남은 경우: orphan 후보로 이동
- blob만 있고 메타데이터가 없는 경우: quarantine 또는 `lost+found` 후보
- 메타데이터는 있는데 blob이 없는 경우: 손상 상태로 표시
- `SQLite` WAL이 남아 있는 경우: DB 복구 후 integrity check 수행

### 6.3 손상 탐지 및 복구

- `metadata.db`는 있는데 blob이 없으면 해당 오브젝트를 `corrupt`로 간주한다.
- blob은 있는데 메타데이터가 없으면 서비스 대상에서 제외하고 운영자 검토 대상으로 둔다.
- `PRAGMA integrity_check` 실패 시 readiness를 실패로 전환한다.

자세한 절차는 [operations-runbook.md](./operations-runbook.md)를 따른다.

### 6.4 버전 관리와 마이그레이션

- 설정 스키마 버전, 메타데이터 스키마 버전, 스토리지 레이아웃 버전을 추적한다.
- 업그레이드 전 백업을 필수 절차로 둔다.
- 롤백은 바이너리만 되돌리는 방식이 아니라 백업 복원까지 포함한다.

## 7. 인증 아키텍처

### 7.1 API

- 요청의 Canonical Request 생성
- `StringToSign` 계산
- Secret Key 기반 `SigV4` 재계산
- 비교 후 승인/거부

### 7.2 UI

- 로그인 성공 시 세션 발급
- 서버 측 세션 저장 또는 서명된 세션 쿠키 사용
- `CSRF` 방어 적용

## 8. 웹 UI 구성

웹 UI는 API와 분리된 별도 백엔드를 두지 않고, 같은 서버의 내부 관리 API를 호출하는 방식이 적절하다.

권장 메뉴:

- Dashboard
- Buckets
- Objects
- Uploads
- Access Keys
- Settings

`Settings` 화면에서는 자유로운 호스트 경로 입력보다, 현재 설정값 조회와 검증에 무게를 두는 편이 안전하다.

## 8.1 Storage Settings 화면 제안

- 현재 `object_root`, `meta_db`, `multipart_root`, `temp_root` 표시
- 각 경로의 존재 여부, 쓰기 가능 여부, 사용량 표시
- 재시작 필요 설정 변경 배지 표시
- 설정 저장 후 재시작 유도

Docker 환경에서는 이 화면이 "호스트 디스크 선택기"가 아니라 "이미 마운트된 컨테이너 경로 관리자" 역할을 한다.

## 9. Docker 아키텍처

권장 이미지는 멀티스테이지 빌드다.

```Dockerfile
FROM golang:1.24 AS build
WORKDIR /src
COPY . .
RUN go build -o /out/hemmins-s3 ./cmd/server

FROM debian:bookworm-slim
WORKDIR /app
COPY --from=build /out/hemmins-s3 /app/hemmins-s3
VOLUME ["/data"]
EXPOSE 9000
ENTRYPOINT ["/app/hemmins-s3"]
```

`docker compose`에서는 최소한 아래 볼륨이 필요하다.

- `/data`

필요시 설정 파일을 별도 마운트한다.

중요한 제약은 아래와 같다.

- Docker가 마운트하지 않은 호스트 경로는 애플리케이션이 사용할 수 없다.
- 웹 UI는 컨테이너 외부 디스크를 직접 연결할 수 없다.
- 여러 디스크를 쓰려면 먼저 여러 볼륨 또는 바인드 마운트를 컨테이너에 연결해야 한다.

즉, Docker의 책임과 애플리케이션의 책임은 분리된다.

- Docker: 어떤 디스크와 폴더를 컨테이너에 연결할지 결정
- 애플리케이션: 연결된 경로 중 무엇을 데이터 경로로 쓸지 결정

운영 절차는 [operations-runbook.md](./operations-runbook.md)를 따른다.

## 10. 코드베이스 구조 제안

```text
cmd/server/main.go
internal/config/
internal/http/s3/
internal/http/ui/
internal/auth/
internal/metadata/
internal/storage/
internal/multipart/
internal/service/
internal/health/
web/
deployments/docker/
```

각 역할은 아래 기준으로 분리한다.

- `internal/http/s3`: S3 라우팅, XML 응답, 헤더 처리
- `internal/auth`: `SigV4`, UI 세션, 접근 키 검증
- `internal/metadata`: `SQLite` 접근 계층
- `internal/storage`: 파일 저장, 스트리밍, 원자적 이동
- `internal/service`: 비즈니스 로직
- `internal/multipart`: 파트 업로드 조립
- `web`: 프런트엔드 정적 자산

## 11. 향후 확장 포인트

- Object Versioning
- Bucket 단위 권한 모델
- S3 Event Notifications
- 외부 인증 연동
- 멀티 디스크 또는 Erasure Coding

하지만 이들은 모두 MVP 이후에 다루는 것이 맞다. 현재 단계에서는 호환성, 무결성, 운영 단순성이 우선이다.
