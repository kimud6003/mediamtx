# 1. Build Stage: Golang을 포함한 이미지에서 빌드
FROM golang:1.23-alpine AS builder

# 필수 패키지 설치
RUN apk update && apk add --no-cache \
    bash \
    git \
    make \
    ffmpeg \
    build-base

# 작업 디렉토리 설정
WORKDIR /app

# 프로젝트 파일 복사
COPY . .

RUN pwd
RUN ls

# Go 모듈 다운로드 및 빌드
RUN go mod tidy
RUN go generate ./...
RUN CGO_ENABLED=0 go build -o /app/mediamtx .

# 2. Run Stage: 경량 이미지로 실행 환경 만들기
FROM alpine:latest

RUN apk update && apk add --no-cache \
    bash \
    git \
    make \
    ffmpeg \
    build-base

# 필요한 라이브러리 설치
RUN apk update && apk add --no-cache \
    bash \
    libstdc++

# 빌드한 바이너리 복사
COPY --from=builder /app/mediamtx /bin/mediamtx

COPY mediamtx.yml /etc/mediamtx/mediamtx.yml

CMD tail -f /dev/null
# 기본 실행 명령
# ENTRYPOINT ["/bin/mediamtx"]

# 기본 환경 변수 설정
ENV MTX_RTSPTRANSPORTS=tcp

