# Development Docs

이 디렉터리는 구현자 관점의 개발 문서를 모아두는 공간이다. 이후 사용자 문서, 운영 문서, API 사용 문서가 추가되더라도 내부 설계 문서가 섞이지 않도록 분리한다.

## 문서 목록

- [제품 요구사항](./product-spec.md)
- [시스템 아키텍처](./system-architecture.md)
- [구현 로드맵](./implementation-roadmap.md)
- [설정 및 배포 모델](./configuration-model.md)
- [S3 호환 계약](./s3-compatibility-matrix.md)
- [보안 모델](./security-model.md)
- [운영 런북](./operations-runbook.md)

## 용도

- 제품 범위와 비범위를 정의한다.
- 구현 전에 아키텍처 결정을 명확히 한다.
- 실제 개발 순서를 고정한다.
- 이후 세부 설계 문서의 상위 인덱스 역할을 한다.

## 문서 맵

- 제품 범위: `product-spec.md`
- 프로토콜 계약: `s3-compatibility-matrix.md`
- 설정 계약: `configuration-model.md`
- 보안 계약: `security-model.md`
- 저장/복구/운영 절차: `operations-runbook.md`
- 구현 구조와 코드 방향: `system-architecture.md`, `implementation-roadmap.md`
