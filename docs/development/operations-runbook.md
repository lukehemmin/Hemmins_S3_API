# 운영 런북

## 1. 목적

이 문서는 단일 노드 환경에서 이 시스템을 백업, 복구, 업그레이드, 장애 대응하는 절차의 기준선을 정의한다.

## 2. 영속 데이터 구성

영속 상태는 아래 네 가지다.

- `config.yaml`
- `metadata.db`
- `object_root`
- `multipart_root`

`temp_root`는 영속 보관 대상이 아니다. 하지만 장애 직후 복구 판단에는 사용될 수 있다.

## 3. 내구성 계약

### 3.1 PUT Object 성공 경계

성공 응답은 아래 조건이 모두 끝난 뒤에만 반환한다.

1. 요청 본문을 `temp_root`의 임시 파일에 스트리밍 저장
2. 임시 파일 `fsync`
3. 최종 오브젝트 경로로 `rename`
4. 대상 디렉터리 `fsync`
5. `SQLite` 트랜잭션 커밋

추가 규칙:

- `SQLite`는 `WAL` 모드와 `synchronous=FULL`을 기본으로 한다.
- `temp_root`와 `object_root`는 같은 파일시스템이어야 한다.
- 위 순서 중 하나라도 실패하면 성공 응답을 반환하지 않는다.

### 3.2 Multipart 완료 경계

`CompleteMultipartUpload`는 아래 순서를 따른다.

1. 파트 순서와 ETag 검증
2. 최종 임시 파일로 병합
3. 최종 임시 파일 `fsync`
4. 최종 오브젝트 경로로 `rename`
5. 대상 디렉터리 `fsync`
6. 메타데이터 트랜잭션 커밋
7. 완료 후 파트 파일 정리

## 4. 시작 시 복구 규칙

### 4.1 상태 매트릭스

| 관측된 상태 | 처리 방식 |
| --- | --- |
| `temp_root` 파일만 있고 DB row 없음 | 유예 시간 이후 orphan 후보로 이동 |
| 최종 blob는 있지만 DB row 없음 | 즉시 서비스하지 않고 quarantine 후보로 이동 |
| DB row는 있는데 blob 없음 | 손상으로 표시, 해당 오브젝트 요청 실패 |
| Multipart 세션만 있고 만료됨 | `AbortMultipartUpload`와 동일하게 정리 |
| `SQLite` WAL 존재 | SQLite 복구 후 무결성 검사 |

### 4.2 Recovery 절차

- 먼저 `SQLite`를 정상적으로 열 수 있는지 확인
- 이후 `temp_root`와 `multipart_root` 정리 후보 스캔
- 마지막으로 blob/메타데이터 불일치 검사

즉시 삭제보다 `quarantine` 또는 `lost+found`로 분리하는 편이 더 안전하다.

## 5. 손상 탐지와 대응

### 5.1 오브젝트 손상

- DB row는 있는데 blob이 없으면 해당 오브젝트를 `corrupt` 상태로 간주
- 요청 시 조용히 없는 객체처럼 숨기지 않는다
- 감사 로그와 메트릭을 남긴다

### 5.2 메타데이터 손상

- `PRAGMA integrity_check` 실패 시 readiness를 실패로 전환
- 자동 수복보다 운영자 개입을 요구한다
- 복구 전까지는 쓰기 트래픽을 받지 않는다

## 6. 백업 절차

### 6.1 권장 백업 단위

반드시 함께 백업해야 하는 것:

- `config.yaml`
- `metadata.db`
- `object_root`
- `auth.master_key` 보관 전략

### 6.2 권장 절차

1. 서비스를 유지보수 모드 또는 쓰기 차단 상태로 전환
2. `SQLite` 백업 API 또는 일관된 파일 백업 수행
3. `object_root` 스냅샷 또는 파일 백업 수행
4. `config.yaml`과 버전 정보를 함께 보관
5. 백업 완료 후 해시 또는 체크섬 기록

`multipart_root`는 복구 필수 대상이 아니다. 미완료 업로드는 복구 후 중단 상태로 정리할 수 있다.

## 7. 복원 절차

1. 새 인스턴스 또는 정지된 인스턴스 준비
2. `config.yaml` 복원
3. `metadata.db` 복원
4. `object_root` 복원
5. `auth.master_key`를 정확히 공급
6. 서버 기동 후 startup recovery 실행
7. 무결성 검사와 샘플 다운로드 테스트 수행

마스터 키가 다르면 저장된 Access Key secret를 해독할 수 없다.

## 8. 업그레이드와 롤백

### 8.1 업그레이드 원칙

- 업그레이드 전 백업은 필수
- 스키마 변경은 버전 번호로 추적
- 마이그레이션은 멱등적이어야 한다
- 실패 시 자동 부분 업그레이드 상태를 남기지 않아야 한다

### 8.2 버전 추적

최소한 아래 버전을 추적한다.

- `config schema version`
- `metadata schema version`
- `storage layout version`

### 8.3 롤백

마이그레이션 후에는 바이너리만 되돌리는 방식의 롤백을 기본으로 보지 않는다.

롤백 기본 절차:

1. 서비스 중지
2. 업그레이드 전 백업 복원
3. 이전 바이너리로 재기동

## 9. Docker 운영 메모

- 백업은 컨테이너 내부가 아니라 마운트된 호스트 볼륨 기준으로 수행한다.
- 업그레이드는 새 이미지로 교체하기 전에 볼륨 백업을 먼저 만든다.
- `docker compose up -d`만으로 업그레이드하지 말고, 사전 백업과 사후 무결성 검사를 포함한다.

## 10. 운영자가 확인해야 할 최소 상태

- `metadata.db` 접근 가능 여부
- `object_root` 쓰기 가능 여부
- 디스크 여유 공간
- orphan 또는 corrupt object 개수
- 마지막 성공 백업 시각
- 현재 스키마 버전

이 문서는 [system-architecture.md](./system-architecture.md)와 함께 운영 기준선으로 유지한다.
