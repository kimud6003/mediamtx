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

# 필수 패키지 설치
RUN apk update && apk add --no-cache \
    bash \
    git \
    make \
    ffmpeg \
    build-base \
    libstdc++ \
    curl

# MinIO Client(mc) 설치
RUN mkdir -p /root/minio-binaries && \
    curl -s https://dl.min.io/client/mc/release/linux-amd64/mc \
    -o /root/minio-binaries/mc && \
    chmod +x /root/minio-binaries/mc

# 환경 변수 설정 (export 대신 ENV 사용)
ENV PATH="/root/minio-binaries:${PATH}"

# 빌드한 바이너리 복사
COPY --from=builder /app/mediamtx /bin/mediamtx

# 설정 파일 복사
COPY mediamtx.yml /etc/mediamtx/mediamtx.yml

COPY rtsp_process.sh /bin/rtsp_process.sh

RUN chmod 777 /bin/rtsp_process.sh

# 환경 변수 설정
ENV MTX_RTSPTRANSPORTS=tcp

ENTRYPOINT ["/bin/mediamtx"]
