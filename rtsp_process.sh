#!/bin/sh
RTSP_PORT=$1
RTSP_PATH=$2
FHD_IMAGE=$3
SMALL_IMAGE=$4
MINIO_BUCKET=$5
ACCESS_KEY=$6
SECRET_KEY=$7
CAMERA_ROI_DEFAULT_SIZE=$8
CAMERA_THUMBNAIL_DEFAULT_SIZE=$9
CAMERA_ID=${10}
CRON_SERVER_HOST=${11}
ORGANIZATION=${12}
API_SERVER_ENDPOINT=${13}
VIDEO_ID=${14}
FILESYSTEM_ID=${15}

if [ -z "$RTSP_PORT" ] || [ -z "$RTSP_PATH" ] || [ -z "$FHD_IMAGE" ] || [ -z "$SMALL_IMAGE" ] || \
   [ -z "$MINIO_BUCKET" ] || [ -z "$ACCESS_KEY" ] || [ -z "$SECRET_KEY" ] || [ -z "$CAMERA_ROI_DEFAULT_SIZE" ] || \
   [ -z "$CAMERA_THUMBNAIL_DEFAULT_SIZE" ] || [ -z "$CAMERA_ID" ] || [ -z "$CRON_SERVER_HOST" ] || [ -z "$ORGANIZATION" ]; then
    echo "Usage: $0 <RTSP_PORT> <RTSP_PATH> <FHD_IMAGE> <SMALL_IMAGE> <MINIO_BUCKET> <ACCESS_KEY> <SECRET_KEY> <CAMERA_ROI_DEFAULT_SIZE> <CAMERA_THUMBNAIL_DEFAULT_SIZE> <CAMERA_ID> <CRON_SERVER_HOST> <ORGANIZATION>"
    exit 1
fi

ffmpeg -i rtsp://localhost:$RTSP_PORT/$RTSP_PATH -vf scale=${CAMERA_ROI_DEFAULT_SIZE} -vframes 1 -y ${FHD_IMAGE}
ffmpeg -i rtsp://localhost:$RTSP_PORT/$RTSP_PATH -vf scale=${CAMERA_THUMBNAIL_DEFAULT_SIZE} -vframes 1 -y ${SMALL_IMAGE}

mc alias set minio http://minio.data-lake.svc.cluster.local:9000 $ACCESS_KEY $SECRET_KEY
mc cp ${FHD_IMAGE} minio/${MINIO_BUCKET}/${FHD_IMAGE}
mc cp ${SMALL_IMAGE} minio/${MINIO_BUCKET}/${SMALL_IMAGE}

rm -f ${FHD_IMAGE}
rm -f ${SMALL_IMAGE}

WIDTH=$(ffprobe -v error -select_streams v:0 -show_entries stream=width -of csv=p=0 "rtsp://localhost:$RTSP_PORT/$RTSP_PATH")
HEIGHT=$(ffprobe -v error -select_streams v:0 -show_entries stream=height -of csv=p=0 "rtsp://localhost:$RTSP_PORT/$RTSP_PATH")

curl -X PATCH ${CRON_SERVER_HOST}/thumbnail/${CAMERA_ID} \
    -H "Content-Type: application/json" \
    -d "$(echo "{
        \"organization\": \"${ORGANIZATION}\",
        \"width\": \"${WIDTH}\",
        \"height\": \"${HEIGHT}\"
    }")"

curl -X POST ${API_SERVER_ENDPOINT} \
  -H "Content-Type: application/json" \
  -H "organization: ${ORGANIZATION}" \
  -d "$(cat <<EOF
{
  "organization": "${ORGANIZATION}",
  "cameraId": ${CAMERA_ID},
  "streamId": "${VIDEO_ID}",
  "filesystemId": ${FILESYSTEM_ID}
}
EOF
)"
echo "Update Completed"

