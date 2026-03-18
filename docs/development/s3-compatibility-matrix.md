# S3 호환 계약

## 1. 목적

이 문서는 MVP 기준 `S3-compatible`의 실제 의미를 고정한다. 구현은 이 계약을 기준으로 동작해야 하며, 문서에 없는 호환성은 보장하지 않는다.

## 2. 전역 계약

### 2.1 주소 지정 방식

- `path-style` 요청을 1급 지원한다.
- `virtual-hosted-style`은 `s3.virtual_host_suffix`가 설정된 경우에만 지원한다.
- `virtual-hosted-style`이 비활성화된 환경에서 해당 형식 요청이 들어오면 `InvalidRequest` 또는 `NotImplemented` 계열의 `S3` 오류를 반환한다.

### 2.2 리전 정책

- MVP는 단일 리전만 지원한다.
- 기본 리전은 `us-east-1`이다.
- `SigV4` scope의 region은 설정된 리전과 일치해야 한다.
- `CreateBucket`의 `LocationConstraint`는 비어 있거나 설정된 리전과 같아야 한다.

### 2.3 버킷 네이밍 규칙

- 길이 `3`자 이상 `63`자 이하
- 소문자 영문, 숫자, `-`, `.`만 허용
- `_` 금지
- IP 주소 형식 금지
- 시작/끝에 `-` 또는 `.` 금지
- 연속된 `..` 금지

### 2.4 키 처리 규칙

- 키는 UTF-8 문자열로 취급한다.
- zero-byte object를 허용한다.
- `/`는 계층 구조를 의미하지 않는다. 목록 조회에서만 `prefix`/`delimiter`로 가상 디렉터리처럼 보일 수 있다.
- 목록 정렬은 UTF-8 바이트 기준 lexicographic order를 따른다.
- trailing slash가 있는 키도 일반 키로 저장한다.

## 3. API 지원 매트릭스

| 영역 | API | 상태 | 비고 |
| --- | --- | --- | --- |
| Service | `ListBuckets` | 지원 | XML 응답 |
| Bucket | `CreateBucket` | 지원 | 단일 리전, 이름 규칙 검증 |
| Bucket | `HeadBucket` | 지원 | 존재/접근 가능 여부 |
| Bucket | `DeleteBucket` | 지원 | 비어 있지 않으면 `BucketNotEmpty` |
| Bucket | `ListObjectsV2` | 지원 | `prefix`, `delimiter`, `continuation-token`, `max-keys`, `encoding-type=url` |
| Object | `PutObject` | 지원 | overwrite 허용, metadata 전체 교체 |
| Object | `GetObject` | 지원 | `Range` 지원 |
| Object | `HeadObject` | 지원 | 조건부 헤더 일부 지원 |
| Object | `DeleteObject` | 지원 | 없는 키 삭제는 멱등 처리 |
| Object | `CopyObject` | 부분 지원 | 동일 인스턴스 내부 복사만 지원 |
| Multipart | `CreateMultipartUpload` | 지원 | 세션 생성 |
| Multipart | `UploadPart` | 지원 | `Content-MD5` 검증 가능 |
| Multipart | `ListParts` | 지원 | 파트 목록 조회 |
| Multipart | `CompleteMultipartUpload` | 지원 | 파트 순서/ETag 검증 |
| Multipart | `AbortMultipartUpload` | 지원 | 임시 파트 제거 |
| Auth | Header-based `SigV4` | 지원 | 단일 리전 |
| Auth | Presigned `GET` | 지원 | 쿼리 서명 검증 |
| Auth | Presigned `PUT` | 지원 | 쿼리 서명 검증 |

## 4. 명시적으로 제외하는 API

아래는 MVP에서 지원하지 않는다.

- `ListObjects` v1
- ACL 관련 API
- Bucket Policy / IAM 관련 API
- Object Tagging
- Versioning
- Lifecycle
- Object Lock
- Server-side Encryption
- Requester Pays
- Select Object Content

미지원 API는 `501 NotImplemented`와 `S3` XML 오류 응답을 반환하는 것을 기본 정책으로 한다.

## 5. 헤더와 의미론

### 5.1 인증 및 무결성 관련 헤더

지원:

- `Authorization`
- `x-amz-date`
- `x-amz-content-sha256`
- `Content-Length`
- `Content-Type`
- `Content-MD5`
- `x-amz-meta-*`

규칙:

- `Content-MD5`가 들어오면 본문과 일치하는지 검증한다.
- `x-amz-content-sha256`는 `SigV4` 검증에 사용한다.
- `UNSIGNED-PAYLOAD`는 Presigned URL 및 일부 단순 업로드 시나리오에 한해 허용한다.
- `STREAMING-AWS4-HMAC-SHA256-PAYLOAD`는 MVP에서 지원하지 않는다.

### 5.2 조건부 요청 헤더

지원:

- `If-Match`
- `If-None-Match`
- `If-Modified-Since`
- `If-Unmodified-Since`

범위:

- `GET Object`
- `HEAD Object`

### 5.3 복사 관련 헤더

지원:

- `x-amz-copy-source`
- `x-amz-metadata-directive`

규칙:

- `COPY`와 `REPLACE`를 지원한다.
- 복사 원본은 같은 인스턴스 내 버킷/키여야 한다.

### 5.4 명시적 미지원 헤더

아래 헤더는 MVP에서 지원하지 않는다.

- `x-amz-server-side-encryption*`
- `x-amz-tagging`
- Object Lock 관련 헤더

이 조합은 `NotImplemented` 또는 `InvalidRequest`로 거부한다.

## 6. 오브젝트 동작 계약

### 6.1 Overwrite

- 같은 버킷/키에 `PutObject`가 들어오면 기존 오브젝트를 원자적으로 교체한다.
- overwrite 시 메타데이터는 병합이 아니라 전체 교체다.
- 마지막 성공 쓰기가 최종 상태가 된다.

### 6.2 ETag

- single-part 업로드의 `ETag`는 본문 MD5 hex를 사용한다.
- multipart 업로드의 `ETag`는 AWS와 동일한 composite MD5 규칙을 따른다.
- 응답 헤더의 `ETag`는 따옴표 포함 문자열로 반환한다.

### 6.3 Range

- 단일 byte range 요청을 지원한다.
- 유효하지 않은 범위는 `416 Requested Range Not Satisfiable`를 반환한다.

## 7. 목록 조회와 키 경계 케이스

- `delimiter`는 `/`를 기준 지원으로 본다.
- `max-keys`는 페이징 상한으로 동작한다.
- `continuation-token`은 불투명 토큰으로 취급한다.
- `encoding-type=url`이 지정되면 키와 공통 접두사는 URL 인코딩된 값으로 반환한다.
- 빈 결과셋도 정상 XML 응답을 반환한다.

## 8. Multipart 계약

- 파트 번호 범위는 `1..10000`
- 마지막 파트를 제외한 각 파트는 최소 `5 MiB`
- `CompleteMultipartUpload`는 파트 번호 오름차순을 요구한다.
- 완료 시 제출된 ETag와 저장된 파트 ETag가 모두 일치해야 한다.
- 완료 성공 후 파트 임시 파일은 정리 대상이 된다.

## 9. 오류 모델과 XML 계약

### 9.1 공통 형식

- 오류 응답은 `S3` XML 형식을 따른다.
- XML namespace는 `http://s3.amazonaws.com/doc/2006-03-01/`
- 기본 필드는 `Code`, `Message`, `Resource`, `RequestId`

### 9.2 최소 보장 오류 코드

- `NoSuchBucket`
- `NoSuchKey`
- `BucketAlreadyExists`
- `BucketAlreadyOwnedByYou`
- `BucketNotEmpty`
- `InvalidBucketName`
- `InvalidRequest`
- `SignatureDoesNotMatch`
- `AccessDenied`
- `NoSuchUpload`
- `InvalidPart`
- `InvalidPartOrder`
- `EntityTooSmall`
- `NotImplemented`
- `InternalError`

## 10. 호환성 우선순위

MVP에서는 아래 순서로 호환성을 맞춘다.

1. AWS CLI와 주요 SDK가 정상 연결되는가
2. 고빈도 헤더와 에러 응답이 `S3` 스타일로 동작하는가
3. Multipart와 Presigned URL이 깨지지 않는가
4. 미지원 기능이 조용히 오동작하지 않고 명시적 오류를 반환하는가

이 문서는 구현과 테스트의 기준선으로 유지한다.
