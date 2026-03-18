# 설정 및 배포 모델

## 1. 목적

이 문서는 이 시스템의 설정 방식, 설정 소스 간 우선순위, 웹 UI에서 허용할 설정 범위, 그리고 Docker 실행 시 스토리지 경로를 어떻게 다룰지 정의한다.

핵심 원칙은 아래와 같다.

- 스토리지 경로와 디스크 마운트는 운영자가 예측 가능하게 다뤄야 한다.
- 컨테이너 외부의 호스트 디스크는 Docker가 연결하고, 애플리케이션은 그 결과만 사용한다.
- 웹 UI는 운영 편의성을 제공하되, 호스트 파일시스템을 임의로 변경하는 도구가 되어서는 안 된다.
- 설정 문서는 구현이 따라야 하는 계약 문서여야 한다.

## 2. 설정 소스와 Source Of Truth

MVP 기준으로 아래 설정 소스를 공식 지원한다.

- 설정 파일: `config.yaml`
- 환경변수: `HEMMINS_*`
- 부트스트랩 전용 환경변수: `HEMMINS_BOOTSTRAP_*`

`.env`는 별도 개념으로 본다.

- 애플리케이션 자체의 정식 설정 포맷은 아니다.
- 로컬 개발과 `docker compose` 변수 주입용으로 사용한다.
- 실제 런타임에서 복잡한 구조 설정은 `config.yaml`이 맡는다.

### 2.1 영구 설정의 Source Of Truth

영구 설정의 기준은 아래처럼 정의한다.

- 지속적으로 유지되는 설정의 canonical source는 `config.yaml`이다.
- 환경변수 오버라이드는 런타임에만 적용되는 외부 관리 값이다.
- 웹 UI는 설정 파일에 저장된 값만 수정할 수 있다.
- 환경변수로 덮어쓴 값은 UI에서 잠금 상태로 표시하고 수정할 수 없다.
- 설정 파일이 읽기 전용이거나 존재하지 않고 생성 권한도 없으면, UI는 읽기 전용 설정 화면으로 동작한다.

### 2.2 부트스트랩 입력

초기 관리자 계정과 초기 루트 접근 키는 영구 설정 파일의 일부로 간주하지 않는다.

- 부트스트랩 입력은 빈 메타데이터 DB에서만 소비한다.
- 소비 후에는 `config.yaml`이 아니라 메타데이터 DB에 저장한다.
- 이미 부트스트랩이 끝난 인스턴스에서 `HEMMINS_BOOTSTRAP_*`가 주입되면 무시하고 경고 로그만 남긴다.

자세한 보안 정책은 [security-model.md](./security-model.md)를 따른다.

## 3. 설정 파일 탐색 순서

권장 탐색 순서는 아래와 같다.

1. CLI 플래그로 지정된 설정 파일
2. `HEMMINS_CONFIG_FILE`
3. 현재 작업 디렉터리의 `config.yaml`

설정 파일을 찾지 못해도 환경변수만으로 기동할 수는 있지만, 영구 설정 변경은 제한된다.

## 4. 설정 우선순위와 병합 규칙

유효 설정은 아래 순서로 계산한다.

1. 기본값
2. 설정 파일
3. 환경변수 오버라이드

### 4.1 병합 규칙

- 병합 단위는 leaf field 기준이다.
- 환경변수는 대응되는 개별 필드만 덮어쓴다.
- 설정 파일에 없는 상위 객체는 기본값과 병합된다.
- 빈 문자열도 값으로 취급한다. 필드가 빈 문자열을 허용하지 않으면 검증 단계에서 실패한다.
- 설정 파일의 문자열 필드는 `${ENV_VAR}` 형식의 환경변수 치환을 지원한다.
- 치환 대상 환경변수가 없고 그 필드가 필수라면 기동 시 실패한다.

### 4.2 예시

- `config.yaml`에 `logging.level: info`가 있고 `HEMMINS_LOGGING_LEVEL=debug`가 있으면 실제 값은 `debug`
- `config.yaml`에 `paths.object_root`만 있고 `paths.temp_root`가 없으면 기본값 또는 환경변수가 보충
- `HEMMINS_SERVER_PUBLIC_ENDPOINT=`처럼 빈 값이 오면 명시적 빈 값으로 해석 후 검증

## 5. 정식 설정 스키마

설정 파일 스키마 버전은 `version` 필드로 관리한다. 현재 문서 기준 스키마 버전은 `1`이다.

### 5.1 Top-Level 필드

| 필드 | 타입 | 필수 | 기본값 | 반영 방식 |
| --- | --- | --- | --- | --- |
| `version` | integer | 아니오 | `1` | 재시작 필요 |
| `server` | object | 예 | 없음 | 혼합 |
| `s3` | object | 예 | 없음 | 혼합 |
| `paths` | object | 예 | 없음 | 재시작 필요 |
| `auth` | object | 예 | 없음 | 재시작 필요 |
| `ui` | object | 예 | 없음 | 혼합 |
| `logging` | object | 아니오 | 기본값 사용 | 즉시 반영 가능 |
| `gc` | object | 아니오 | 기본값 사용 | 즉시 반영 가능 |

### 5.2 `server`

| 필드 | 타입 | 필수 | 기본값 | 반영 방식 | 설명 |
| --- | --- | --- | --- | --- | --- |
| `server.listen` | string | 아니오 | `:9000` | 재시작 필요 | HTTP listen address |
| `server.public_endpoint` | string | 아니오 | 빈 값 | 즉시 반영 가능 | 외부 공개 URL, Presigned URL 기준 |
| `server.enable_ui` | boolean | 아니오 | `true` | 재시작 필요 | 관리자 UI 제공 여부 |
| `server.trust_proxy_headers` | boolean | 아니오 | `false` | 재시작 필요 | `X-Forwarded-*` 신뢰 여부 |

### 5.3 `s3`

| 필드 | 타입 | 필수 | 기본값 | 반영 방식 | 설명 |
| --- | --- | --- | --- | --- | --- |
| `s3.region` | string | 아니오 | `us-east-1` | 재시작 필요 | 단일 리전 이름 |
| `s3.virtual_host_suffix` | string | 아니오 | 빈 값 | 재시작 필요 | `bucket.<suffix>` 스타일 허용 도메인 |
| `s3.max_presign_ttl` | duration | 아니오 | `24h` | 즉시 반영 가능 | Presigned URL 최대 허용 TTL |

### 5.4 `paths`

| 필드 | 타입 | 필수 | 기본값 | 반영 방식 | 설명 |
| --- | --- | --- | --- | --- | --- |
| `paths.meta_db` | string | 예 | 없음 | 재시작 필요 | `SQLite` DB 파일 경로 |
| `paths.object_root` | string | 예 | 없음 | 재시작 필요 | 최종 오브젝트 저장 루트 |
| `paths.multipart_root` | string | 예 | 없음 | 재시작 필요 | Multipart 파트 저장 루트 |
| `paths.temp_root` | string | 예 | 없음 | 재시작 필요 | 임시 파일 저장 루트 |
| `paths.log_root` | string | 아니오 | `/data/logs` | 재시작 필요 | 파일 로그 출력 루트 |

### 5.5 `auth`

| 필드 | 타입 | 필수 | 기본값 | 반영 방식 | 설명 |
| --- | --- | --- | --- | --- | --- |
| `auth.master_key` | string | 예 | 없음 | 재시작 필요 | 비밀값 암호화용 마스터 키 |

### 5.6 `ui`

| 필드 | 타입 | 필수 | 기본값 | 반영 방식 | 설명 |
| --- | --- | --- | --- | --- | --- |
| `ui.session_ttl` | duration | 아니오 | `12h` | 즉시 반영 가능 | 절대 세션 만료 시간 |
| `ui.session_idle_ttl` | duration | 아니오 | `30m` | 즉시 반영 가능 | 유휴 세션 만료 시간 |

### 5.7 `logging`

| 필드 | 타입 | 필수 | 기본값 | 반영 방식 | 설명 |
| --- | --- | --- | --- | --- | --- |
| `logging.level` | enum | 아니오 | `info` | 즉시 반영 가능 | `debug`, `info`, `warn`, `error` |
| `logging.access_log` | boolean | 아니오 | `true` | 즉시 반영 가능 | 요청 로그 출력 여부 |

### 5.8 `gc`

| 필드 | 타입 | 필수 | 기본값 | 반영 방식 | 설명 |
| --- | --- | --- | --- | --- | --- |
| `gc.orphan_scan_interval` | duration | 아니오 | `24h` | 즉시 반영 가능 | orphan 스캔 주기 |
| `gc.orphan_grace_period` | duration | 아니오 | `1h` | 즉시 반영 가능 | orphan 확정 전 유예 시간 |
| `gc.multipart_expiry` | duration | 아니오 | `24h` | 즉시 반영 가능 | 미완료 Multipart 만료 시간 |

## 6. 부트스트랩 전용 환경변수

초기 설치용 입력은 아래 환경변수로 받는다.

- `HEMMINS_BOOTSTRAP_ADMIN_USERNAME`
- `HEMMINS_BOOTSTRAP_ADMIN_PASSWORD`
- `HEMMINS_BOOTSTRAP_ROOT_ACCESS_KEY`
- `HEMMINS_BOOTSTRAP_ROOT_SECRET_KEY`

계약은 아래와 같다.

- 메타데이터 DB가 비어 있을 때만 사용한다.
- 사용 후에는 DB에 저장하고 다시 재표시하지 않는다.
- 관리자 비밀번호는 해시로 저장한다.
- Access Key 비밀값은 `auth.master_key`로 암호화해 저장한다.
- 이후에는 UI 또는 관리 API를 통해 회전한다.

## 7. 검증 규칙

### 7.1 일반 검증

- 모든 `paths.*`는 절대 경로여야 한다.
- `server.public_endpoint`는 `http://` 또는 `https://` 절대 URL이어야 한다.
- `s3.region`은 소문자, 숫자, 하이픈만 허용한다.
- `ui.session_idle_ttl`은 `ui.session_ttl`보다 길 수 없다.
- `auth.master_key`는 충분한 엔트로피를 가져야 하며 최소 32바이트 이상을 권장한다.

### 7.2 경로 검증

- `paths.meta_db`는 파일 경로여야 하며 부모 디렉터리는 생성 가능하거나 이미 존재해야 한다.
- `paths.object_root`, `paths.multipart_root`, `paths.temp_root`는 서로 다른 디렉터리여야 한다.
- `paths.temp_root`와 `paths.object_root`는 같은 파일시스템에 있어야 한다.
- `paths.multipart_root` 역시 가능하면 `paths.object_root`와 같은 파일시스템을 권장한다.
- 경로가 존재하면 서버 시작 시 읽기/쓰기 권한을 검증한다.

### 7.3 배포 검증

- `server.trust_proxy_headers=true`이면 신뢰 가능한 리버스 프록시 뒤에서만 사용해야 한다.
- `s3.virtual_host_suffix`를 쓰려면 DNS와 TLS가 그 suffix를 커버해야 한다.
- Docker에서는 경로 유효성 검사가 컨테이너 내부 경로 기준으로 수행된다.

## 8. Reload Policy

### 8.1 즉시 반영 가능한 설정

- `server.public_endpoint`
- `s3.max_presign_ttl`
- `ui.session_ttl`
- `ui.session_idle_ttl`
- `logging.*`
- `gc.*`

### 8.2 재시작이 필요한 설정

- `server.listen`
- `server.enable_ui`
- `server.trust_proxy_headers`
- `s3.region`
- `s3.virtual_host_suffix`
- `paths.*`
- `auth.master_key`

### 8.3 UI 저장 동작

- 재시작이 필요한 값을 저장하면 현재 프로세스에는 즉시 반영하지 않는다.
- UI는 해당 값을 `pending restart` 상태로 표시한다.
- 재시작 후 새 유효 설정이 적용된다.
- 환경변수 오버라이드로 잠긴 필드는 UI에서 편집할 수 없다.

## 9. Invalid Config 처리 정책

### 9.1 시작 시

- 유효 설정 계산 후 검증에 실패하면 서비스는 fail-fast로 종료한다.
- 마지막 정상 설정으로 자동 롤백해 조용히 기동하는 방식은 사용하지 않는다.
- `SQLite` 손상이나 필수 경로 접근 실패가 있으면 `/readyz`를 `200`으로 만들지 않는다.

### 9.2 UI 저장 시

- UI는 새 설정을 저장하기 전에 전체 검증을 수행한다.
- 유효하지 않은 설정은 저장 자체를 거부한다.
- 저장은 임시 파일 작성, 검증, 백업 생성, 원자적 교체 순서로 수행한다.
- 직전 정상 설정은 `config.yaml.bak`로 보관한다.

## 10. 웹 UI에서 허용할 설정 범위

### 10.1 웹 UI에서 보여줘야 하는 것

- 현재 유효 설정값
- 환경변수로 잠긴 필드 여부
- 메타데이터 DB 경로
- 오브젝트 저장 경로
- Multipart 임시 경로
- 디스크 사용량과 여유 공간
- 설정 변경 시 재시작 필요 여부

### 10.2 웹 UI에서 수정 가능하게 해도 되는 것

초기 버전에서는 아래 정도만 허용하는 것이 안전하다.

- `server.public_endpoint`
- `s3.max_presign_ttl`
- `logging.level`
- `logging.access_log`
- `ui.session_ttl`
- `ui.session_idle_ttl`
- 접근 키 생성/폐기
- 관리자 계정 비밀번호 변경

### 10.3 웹 UI에서 바로 수정하면 안 되는 것

아래 항목은 런타임에 자유 수정하게 두면 위험하다.

- `paths.*`
- `auth.master_key`
- `server.listen`
- `server.enable_ui`
- `server.trust_proxy_headers`
- `s3.region`
- `s3.virtual_host_suffix`

이 항목들은 프로세스 재시작과 경로 유효성 검증이 필요하다.

## 11. 스토리지 경로 변경 정책

### 11.1 Bare Metal / VM

- 설정 파일 또는 환경변수로 지정
- 선택적으로 "초기 설치 마법사"에서 1회 설정 가능
- 변경 시 서버가 새 설정을 저장하고 재시작을 요구

### 11.2 Docker

Docker에서는 애플리케이션이 호스트 디스크를 직접 고를 수 없다. 먼저 Docker가 볼륨 또는 바인드 마운트를 컨테이너 내부 경로에 연결해야 한다.

즉, UI는 아래까지만 할 수 있다.

- 이미 마운트된 컨테이너 내부 경로를 보여준다.
- 그중 어떤 경로가 유효한 저장 경로인지 검증한다.
- 선택 결과를 설정 파일에 저장하고 재시작을 유도한다.

UI가 할 수 없는 것은 아래다.

- 호스트의 `/mnt/disk1` 같은 실제 경로를 직접 마운트
- 새 Docker volume 생성
- 컨테이너 외부 디스크 검색

이건 전부 Docker 또는 오케스트레이터가 해야 할 일이다.

## 12. 다중 디스크 범위

MVP는 과하게 넓히지 않는 편이 맞다.

- 단일 `object_root`
- 별도 `meta_db` 경로
- 별도 `temp_root` 경로
- UI에서는 경로를 조회 중심으로 제공

다중 디스크는 후속 확장으로 둔다. 이유는 아래와 같다.

- 오브젝트 배치 정책이 필요하다.
- 디스크 장애 처리 정책이 필요하다.
- 디스크별 사용량 집계와 경고가 필요하다.
- 객체별 저장 위치 추적이 더 중요해진다.

## 13. 설정 파일 예시

```yaml
version: 1

server:
  listen: ":9000"
  public_endpoint: "http://localhost:9000"
  enable_ui: true
  trust_proxy_headers: false

s3:
  region: "us-east-1"
  virtual_host_suffix: ""
  max_presign_ttl: "24h"

paths:
  meta_db: "/data/meta/metadata.db"
  object_root: "/data/objects"
  multipart_root: "/data/multipart"
  temp_root: "/data/tmp"
  log_root: "/data/logs"

auth:
  master_key: "${HEMMINS_MASTER_KEY}"

ui:
  session_ttl: "12h"
  session_idle_ttl: "30m"

logging:
  level: "info"
  access_log: true

gc:
  orphan_scan_interval: "24h"
  orphan_grace_period: "1h"
  multipart_expiry: "24h"
```

## 14. 환경변수 예시

```env
HEMMINS_SERVER_LISTEN=:9000
HEMMINS_SERVER_PUBLIC_ENDPOINT=http://localhost:9000
HEMMINS_S3_REGION=us-east-1
HEMMINS_PATHS_META_DB=/data/meta/metadata.db
HEMMINS_PATHS_OBJECT_ROOT=/data/objects
HEMMINS_PATHS_MULTIPART_ROOT=/data/multipart
HEMMINS_PATHS_TEMP_ROOT=/data/tmp
HEMMINS_AUTH_MASTER_KEY=change-this-master-key
HEMMINS_BOOTSTRAP_ADMIN_USERNAME=admin
HEMMINS_BOOTSTRAP_ADMIN_PASSWORD=change-me
HEMMINS_BOOTSTRAP_ROOT_ACCESS_KEY=rootadmin
HEMMINS_BOOTSTRAP_ROOT_SECRET_KEY=change-me
```

## 15. Docker 배포 모델

### 15.1 가장 단순한 방식

컨테이너 내부 `/data` 하나만 영속 볼륨으로 둔다.

```yaml
services:
  hemmins-s3:
    image: hemmins/s3:dev
    ports:
      - "9000:9000"
    environment:
      HEMMINS_SERVER_LISTEN: ":9000"
      HEMMINS_S3_REGION: "us-east-1"
      HEMMINS_PATHS_META_DB: "/data/meta/metadata.db"
      HEMMINS_PATHS_OBJECT_ROOT: "/data/objects"
      HEMMINS_PATHS_MULTIPART_ROOT: "/data/multipart"
      HEMMINS_PATHS_TEMP_ROOT: "/data/tmp"
      HEMMINS_AUTH_MASTER_KEY: "${HEMMINS_AUTH_MASTER_KEY}"
      HEMMINS_BOOTSTRAP_ADMIN_USERNAME: "${HEMMINS_BOOTSTRAP_ADMIN_USERNAME}"
      HEMMINS_BOOTSTRAP_ADMIN_PASSWORD: "${HEMMINS_BOOTSTRAP_ADMIN_PASSWORD}"
      HEMMINS_BOOTSTRAP_ROOT_ACCESS_KEY: "${HEMMINS_BOOTSTRAP_ROOT_ACCESS_KEY}"
      HEMMINS_BOOTSTRAP_ROOT_SECRET_KEY: "${HEMMINS_BOOTSTRAP_ROOT_SECRET_KEY}"
    volumes:
      - hemmins-data:/data

volumes:
  hemmins-data:
```

### 15.2 경로를 분리하는 방식

메타데이터와 오브젝트 경로를 분리할 수 있다.

```yaml
services:
  hemmins-s3:
    image: hemmins/s3:dev
    ports:
      - "9000:9000"
    volumes:
      - /srv/hemmins/meta:/data/meta
      - /srv/hemmins/objects:/data/objects
      - /srv/hemmins/multipart:/data/multipart
      - /srv/hemmins/tmp:/data/tmp
```

### 15.3 다중 디스크를 미리 마운트하는 방식

여러 디스크를 나중에 쓰고 싶다면 먼저 컨테이너에 다 마운트해야 한다.

```yaml
services:
  hemmins-s3:
    image: hemmins/s3:dev
    volumes:
      - /mnt/disk1:/mnt/storage/disk1
      - /mnt/disk2:/mnt/storage/disk2
      - /srv/hemmins/meta:/data/meta
      - /srv/hemmins/tmp:/data/tmp
```

그 다음 애플리케이션 설정에서 `/mnt/storage/disk1`, `/mnt/storage/disk2`를 참조한다.

## 16. 문서 연결

이 주제는 아래 문서와 함께 읽는 것이 맞다.

- [제품 요구사항](./product-spec.md)
- [S3 호환 계약](./s3-compatibility-matrix.md)
- [보안 모델](./security-model.md)
- [운영 런북](./operations-runbook.md)
