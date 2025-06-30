// @title MediaMTX API
// @version 1.0
// @description MediaMTX configuration API
// @BasePath /v3

// Package api contains the API server.
package api

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/bluenviron/mediamtx/internal/auth"
	"github.com/bluenviron/mediamtx/internal/conf"
	"github.com/bluenviron/mediamtx/internal/conf/jsonwrapper"
	"github.com/bluenviron/mediamtx/internal/defs"
	"github.com/bluenviron/mediamtx/internal/logger"
	"github.com/bluenviron/mediamtx/internal/protocols/httpp"
	"github.com/bluenviron/mediamtx/internal/recordstore"
	"github.com/bluenviron/mediamtx/internal/restrictnetwork"
	"github.com/bluenviron/mediamtx/internal/servers/hls"
	"github.com/bluenviron/mediamtx/internal/servers/rtmp"
	"github.com/bluenviron/mediamtx/internal/servers/rtsp"
	"github.com/bluenviron/mediamtx/internal/servers/srt"
	"github.com/bluenviron/mediamtx/internal/servers/webrtc"

	_ "github.com/bluenviron/mediamtx/docs"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
)

func interfaceIsEmpty(i interface{}) bool {
	return reflect.ValueOf(i).Kind() != reflect.Ptr || reflect.ValueOf(i).IsNil()
}

func sortedKeys(paths map[string]*conf.Path) []string {
	ret := make([]string, len(paths))
	i := 0
	for name := range paths {
		ret[i] = name
		i++
	}
	sort.Strings(ret)
	return ret
}

func paramName(ctx *gin.Context) (string, bool) {
	name := ctx.Param("name")

	if len(name) < 2 || name[0] != '/' {
		return "", false
	}

	return name[1:], true
}

func recordingsOfPath(
	pathConf *conf.Path,
	pathName string,
) *defs.APIRecording {
	ret := &defs.APIRecording{
		Name: pathName,
	}

	segments, _ := recordstore.FindSegments(pathConf, pathName, nil, nil)

	ret.Segments = make([]*defs.APIRecordingSegment, len(segments))

	for i, seg := range segments {
		ret.Segments[i] = &defs.APIRecordingSegment{
			Start: seg.Start,
		}
	}

	return ret
}

type apiAuthManager interface {
	Authenticate(req *auth.Request) error
	RefreshJWTJWKS()
}

type apiParent interface {
	logger.Writer
	APIConfigSet(conf *conf.Conf)
}

// API is an API server.
type API struct {
	Address        string
	Encryption     bool
	ServerKey      string
	ServerCert     string
	AllowOrigin    string
	TrustedProxies conf.IPNetworks
	ReadTimeout    conf.Duration
	Conf           *conf.Conf
	AuthManager    apiAuthManager
	PathManager    defs.APIPathManager
	RTSPServer     defs.APIRTSPServer
	RTSPSServer    defs.APIRTSPServer
	RTMPServer     defs.APIRTMPServer
	RTMPSServer    defs.APIRTMPServer
	HLSServer      defs.APIHLSServer
	WebRTCServer   defs.APIWebRTCServer
	SRTServer      defs.APISRTServer
	Parent         apiParent

	httpServer *httpp.Server
	mutex      sync.RWMutex
}

// Initialize initializes API.
func (a *API) Initialize() error {
	router := gin.New()
	router.SetTrustedProxies(a.TrustedProxies.ToTrustedProxies()) //nolint:errcheck

	router.Use(a.middlewareOrigin)
	router.Use(a.middlewareAuth)

	router.GET("/api-docs", func(c *gin.Context) {
		c.Redirect(301, "/api-docs/index.html#")
	})
	router.GET("/api-docs/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))
	group := router.Group("/v3")

	group.POST("/auth/jwks/refresh", a.onAuthJwksRefresh)

	group.GET("/config/global/get", a.onConfigGlobalGet)
	group.PATCH("/config/global/patch", a.onConfigGlobalPatch)

	group.GET("/config/pathdefaults/get", a.onConfigPathDefaultsGet)
	group.PATCH("/config/pathdefaults/patch", a.onConfigPathDefaultsPatch)

	group.GET("/config/paths/list", a.onConfigPathsList)
	group.GET("/config/paths/get/*name", a.onConfigPathsGet)
	group.POST("/config/paths/add/*name", a.onConfigPathsAdd)
	group.PATCH("/config/paths/patch/*name", a.onConfigPathsPatch)
	group.POST("/config/paths/replace/*name", a.onConfigPathsReplace)
	group.DELETE("/config/paths/delete/*name", a.onConfigPathsDelete)

	group.GET("/paths/list", a.onPathsList)
	group.GET("/paths/get/*name", a.onPathsGet)

	group.POST("/thumbnail/upload", a.handleThumbnailUpload)

	if !interfaceIsEmpty(a.HLSServer) {
		group.GET("/hlsmuxers/list", a.onHLSMuxersList)
		group.GET("/hlsmuxers/get/*name", a.onHLSMuxersGet)
	}

	if !interfaceIsEmpty(a.RTSPServer) {
		group.GET("/rtspconns/list", a.onRTSPConnsList)
		group.GET("/rtspconns/get/:id", a.onRTSPConnsGet)
		group.GET("/rtspsessions/list", a.onRTSPSessionsList)
		group.GET("/rtspsessions/get/:id", a.onRTSPSessionsGet)
		group.POST("/rtspsessions/kick/:id", a.onRTSPSessionsKick)
	}

	if !interfaceIsEmpty(a.RTSPSServer) {
		group.GET("/rtspsconns/list", a.onRTSPSConnsList)
		group.GET("/rtspsconns/get/:id", a.onRTSPSConnsGet)
		group.GET("/rtspssessions/list", a.onRTSPSSessionsList)
		group.GET("/rtspssessions/get/:id", a.onRTSPSSessionsGet)
		group.POST("/rtspssessions/kick/:id", a.onRTSPSSessionsKick)
	}

	if !interfaceIsEmpty(a.RTMPServer) {
		group.GET("/rtmpconns/list", a.onRTMPConnsList)
		group.GET("/rtmpconns/get/:id", a.onRTMPConnsGet)
		group.POST("/rtmpconns/kick/:id", a.onRTMPConnsKick)
	}

	if !interfaceIsEmpty(a.RTMPSServer) {
		group.GET("/rtmpsconns/list", a.onRTMPSConnsList)
		group.GET("/rtmpsconns/get/:id", a.onRTMPSConnsGet)
		group.POST("/rtmpsconns/kick/:id", a.onRTMPSConnsKick)
	}

	if !interfaceIsEmpty(a.WebRTCServer) {
		group.GET("/webrtcsessions/list", a.onWebRTCSessionsList)
		group.GET("/webrtcsessions/get/:id", a.onWebRTCSessionsGet)
		group.POST("/webrtcsessions/kick/:id", a.onWebRTCSessionsKick)
	}

	if !interfaceIsEmpty(a.SRTServer) {
		group.GET("/srtconns/list", a.onSRTConnsList)
		group.GET("/srtconns/get/:id", a.onSRTConnsGet)
		group.POST("/srtconns/kick/:id", a.onSRTConnsKick)
	}

	group.GET("/recordings/list", a.onRecordingsList)
	group.GET("/recordings/get/*name", a.onRecordingsGet)
	group.DELETE("/recordings/deletesegment", a.onRecordingDeleteSegment)

	network, address := restrictnetwork.Restrict("tcp", a.Address)

	a.httpServer = &httpp.Server{
		Network:     network,
		Address:     address,
		ReadTimeout: time.Duration(a.ReadTimeout),
		Encryption:  a.Encryption,
		ServerCert:  a.ServerCert,
		ServerKey:   a.ServerKey,
		Handler:     router,
		Parent:      a,
	}
	err := a.httpServer.Initialize()
	if err != nil {
		return err
	}

	a.Log(logger.Info, "listener opened on "+address)

	return nil
}

// Close closes the API.
func (a *API) Close() {
	a.Log(logger.Info, "listener is closing")
	a.httpServer.Close()
}

// Log implements logger.Writer.
func (a *API) Log(level logger.Level, format string, args ...interface{}) {
	a.Parent.Log(level, "[API] "+format, args...)
}

func (a *API) writeError(ctx *gin.Context, status int, err error) {
	// show error in logs
	a.Log(logger.Error, err.Error())

	// add error to response
	ctx.JSON(status, &defs.APIError{
		Error: err.Error(),
	})
}

func (a *API) middlewareOrigin(ctx *gin.Context) {
	ctx.Header("Access-Control-Allow-Origin", a.AllowOrigin)
	ctx.Header("Access-Control-Allow-Credentials", "true")

	// preflight requests
	if ctx.Request.Method == http.MethodOptions &&
		ctx.Request.Header.Get("Access-Control-Request-Method") != "" {
		ctx.Header("Access-Control-Allow-Methods", "OPTIONS, GET, POST, PATCH, DELETE")
		ctx.Header("Access-Control-Allow-Headers", "Authorization, Content-Type")
		ctx.AbortWithStatus(http.StatusNoContent)
		return
	}
}

func (a *API) middlewareAuth(ctx *gin.Context) {
	req := &auth.Request{
		Action:      conf.AuthActionAPI,
		Query:       ctx.Request.URL.RawQuery,
		Credentials: httpp.Credentials(ctx.Request),
		IP:          net.ParseIP(ctx.ClientIP()),
	}

	err := a.AuthManager.Authenticate(req)
	if err != nil {
		if err.(auth.Error).AskCredentials { //nolint:errorlint
			ctx.Header("WWW-Authenticate", `Basic realm="mediamtx"`)
			ctx.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		// wait some seconds to mitigate brute force attacks
		<-time.After(auth.PauseAfterError)

		ctx.AbortWithStatus(http.StatusUnauthorized)
		return
	}
}

// @Summary Capture thumbnails and update metadata
// @Tags thumbnail
// @Accept json
// @Produce json
// @Param request body defs.ThumbnailUploadRequest true "Thumbnail request payload"
// @Success 200 {object} map[string]string
// @Failure 400 {object} defs.APIError
// @Failure 500 {object} defs.APIError
// @Router /v3/thumbnail/upload [post]
func (a *API) handleThumbnailUpload(ctx *gin.Context) {
	var req defs.ThumbnailUploadRequest

	if err := ctx.ShouldBindJSON(&req); err != nil {
		a.writeError(ctx, http.StatusBadRequest, err)
		return
	}

	// TODO: Path랑 Port는 환경변수가 없어서 api server 단에서 수정 필요
	// TODO: rtspHost는 localhost로 변경 필요
	const rtspHost = "127.0.0.1"
	// FFmpeg 명령어 실행
	cmd := exec.Command("bash", "-c", fmt.Sprintf(`ffmpeg -y -i "rtsp://%s:%d/%s" -vf scale=%s -vframes 1 %s && ffmpeg -y -i "rtsp://%s:%d/%s" -vf scale=%s -vframes 1 %s`,
		rtspHost, req.RTSPPort, req.RTSPPath, req.CameraRoiDefaultSize, req.FHDImage,
		rtspHost, req.RTSPPort, req.RTSPPath, req.CameraThumbnailDefaultSize, req.SmallImage,
	))

	out, err := cmd.CombinedOutput()
	if err != nil {
		a.writeError(ctx, http.StatusInternalServerError, fmt.Errorf("FFmpeg error: %s\n%s", err.Error(), out))
		return
	}
	a.Log(logger.Info, "FFmpeg thumbnails generated successfully for cameraID=%s", req.CameraID)

	// TODO: minio url 변경 필요
	// const minioUrl = "http://minio.data-lake.svc.cluster.local:9000"
	const minioUrl = "http://172.168.47.35:32702"
	// mc 업로드
	mcCmd := exec.Command("bash", "-c", fmt.Sprintf(`mc alias set minio %s %s %s &&
		mc cp %s minio/%s/%s &&
		mc cp %s minio/%s/%s`,
		minioUrl, req.AccessKey, req.SecretKey,
		req.FHDImage, req.MinioBucket, req.FHDImage,
		req.SmallImage, req.MinioBucket, req.SmallImage,
	))

	mcOut, err := mcCmd.CombinedOutput()
	if err != nil {
		a.writeError(ctx, http.StatusInternalServerError, fmt.Errorf("MinIO upload error: %s\n%s", err.Error(), mcOut))
		return
	}
	a.Log(logger.Info, "MinIO upload successfully for cameraID=%s", req.CameraID)

	// ffprobe 정보 수집
	width := probeValue(ctx, req.RTSPPort, req.RTSPPath, "width")
	height := probeValue(ctx, req.RTSPPort, req.RTSPPath, "height")
	fps := probeFPS(ctx, req.RTSPPort, req.RTSPPath)

	thumbnailPayload := fmt.Sprintf(`{
		"organization": "%s",
		"width": "%s",
		"height": "%s",
		"fps": "%s"
	}`, req.Organization, width, height, fps)

	reqPatch, err := http.NewRequest(
		http.MethodPatch,
		req.CronServerHost+"/thumbnail/"+req.CameraID,
		bytes.NewBufferString(thumbnailPayload),
	)

	if err != nil {
		a.writeError(ctx, http.StatusInternalServerError, fmt.Errorf("Failed to create PATCH request: %v", err))
		return
	}

	reqPatch.Header.Set("Content-Type", "application/json")

	resp1, err := http.DefaultClient.Do(reqPatch)
	if err != nil {
		a.writeError(ctx, http.StatusInternalServerError, fmt.Errorf("Cron patch error: %v", err))
		return
	}
	defer resp1.Body.Close()

	if resp1.StatusCode < 200 || resp1.StatusCode >= 300 {
		bodyBytes, _ := io.ReadAll(resp1.Body)
		a.writeError(ctx, http.StatusBadGateway, fmt.Errorf(
			"Cron server returned %d: %s", resp1.StatusCode, string(bodyBytes),
		))
		return
	}

	a.Log(logger.Info, "Request to Cron server for updating metadata successfully in camera=%s", req.CameraID)

	streamPayload := fmt.Sprintf(`{
		"organization": "%s",
		"cameraId": %s,
		"streamId": "%s",
		"filesystemId": %s
	}`, req.Organization, req.CameraID, req.VideoID, req.FilesystemID)

	resp2, err := http.Post(
		req.APIServerEndpoint,
		"application/json",
		bytes.NewBufferString(streamPayload),
	)
	if err != nil {
		a.writeError(ctx, http.StatusInternalServerError, fmt.Errorf("Metadata post error: %v", err))
		return
	}
	defer resp2.Body.Close()

	if resp2.StatusCode < 200 || resp2.StatusCode >= 300 {
		bodyBytes, _ := io.ReadAll(resp2.Body)
		a.writeError(ctx, http.StatusBadGateway, fmt.Errorf(
			"API server returned %d: %s", resp2.StatusCode, string(bodyBytes),
		))
		return
	}

	a.Log(logger.Info, "Request to Api server for request AI Server successfully in camera=%s", req.CameraID)
	ctx.JSON(http.StatusOK, gin.H{"status": "thumbnail captured and uploaded"})
}

func probeValue(ctx *gin.Context, port int, path, key string) string {
	cmd := exec.Command("bash", "-c", fmt.Sprintf(`ffprobe -v error -select_streams v:0 -show_entries stream=%s -of csv=p=0 "rtsp://localhost:%d/%s"`, key, port, path))
	out, _ := cmd.Output()
	return strings.TrimSpace(string(out))
}

func probeFPS(ctx *gin.Context, port int, path string) string {
	cmd := exec.Command("bash", "-c", fmt.Sprintf(`ffprobe -v error -select_streams v:0 -show_entries stream=r_frame_rate -of csv=p=0 "rtsp://localhost:%d/%s"`, port, path))
	out, _ := cmd.Output()
	parts := strings.Split(strings.TrimSpace(string(out)), "/")
	if len(parts) == 2 && parts[1] != "0" {
		num, _ := strconv.ParseFloat(parts[0], 64)
		den, _ := strconv.ParseFloat(parts[1], 64)
		return fmt.Sprintf("%.2f", num/den)
	}
	return parts[0]
}

// @Summary Get global configuration
// @Tags config
// @Produce json
// @Success 200 {object} conf.Global
// @Router /v3/config/global/get [get]
func (a *API) onConfigGlobalGet(ctx *gin.Context) {
	a.mutex.RLock()
	c := a.Conf
	a.mutex.RUnlock()

	ctx.JSON(http.StatusOK, c.Global())
}

// @Summary Patch global configuration
// @Tags config
// @Accept json
// @Produce json
// @Param config body conf.OptionalGlobal true "Global configuration patch"
// @Success 200
// @Failure 400 {object} defs.APIError
// @Router /v3/config/global/patch [patch]
func (a *API) onConfigGlobalPatch(ctx *gin.Context) {
	var c conf.OptionalGlobal
	err := jsonwrapper.Decode(ctx.Request.Body, &c)
	if err != nil {
		a.writeError(ctx, http.StatusBadRequest, err)
		return
	}

	a.mutex.Lock()
	defer a.mutex.Unlock()

	newConf := a.Conf.Clone()

	newConf.PatchGlobal(&c)

	err = newConf.Validate(nil)
	if err != nil {
		a.writeError(ctx, http.StatusBadRequest, err)
		return
	}

	a.Conf = newConf

	// since reloading the configuration can cause the shutdown of the API,
	// call it in a goroutine
	go a.Parent.APIConfigSet(newConf)

	ctx.Status(http.StatusOK)
}

// onConfigPathDefaultsGet returns the default path config.
//
// @Summary Get default path configuration
// @Tags config
// @Produce json
// @Success 200 {object} conf.Path
// @Router /v3/config/pathdefaults/get [get]
func (a *API) onConfigPathDefaultsGet(ctx *gin.Context) {
	a.mutex.RLock()
	c := a.Conf
	a.mutex.RUnlock()

	ctx.JSON(http.StatusOK, c.PathDefaults)
}

// @Summary Patch default path configuration
// @Tags config
// @Accept json
// @Produce json
// @Param config body conf.OptionalPath true "Default path configuration patch"
// @Success 200
// @Failure 400 {object} defs.APIError
// @Router /v3/config/pathdefaults/patch [patch]
func (a *API) onConfigPathDefaultsPatch(ctx *gin.Context) {
	var p conf.OptionalPath
	err := jsonwrapper.Decode(ctx.Request.Body, &p)
	if err != nil {
		a.writeError(ctx, http.StatusBadRequest, err)
		return
	}

	a.mutex.Lock()
	defer a.mutex.Unlock()

	newConf := a.Conf.Clone()

	newConf.PatchPathDefaults(&p)

	err = newConf.Validate(nil)
	if err != nil {
		a.writeError(ctx, http.StatusBadRequest, err)
		return
	}

	a.Conf = newConf
	a.Parent.APIConfigSet(newConf)

	ctx.Status(http.StatusOK)
}

// @Summary List all configured paths
// @Tags config
// @Produce json
// @Param itemsPerPage query int false "Items per page"
// @Param page query int false "Page number"
// @Success 200 {object} defs.APIPathConfList
// @Failure 400 {object} defs.APIError
// @Router /v3/config/paths/list [get]
func (a *API) onConfigPathsList(ctx *gin.Context) {
	a.mutex.RLock()
	c := a.Conf
	a.mutex.RUnlock()

	data := &defs.APIPathConfList{
		Items: make([]*conf.Path, len(c.Paths)),
	}

	for i, key := range sortedKeys(c.Paths) {
		data.Items[i] = c.Paths[key]
	}

	data.ItemCount = len(data.Items)
	pageCount, err := paginate(&data.Items, ctx.Query("itemsPerPage"), ctx.Query("page"))
	if err != nil {
		a.writeError(ctx, http.StatusBadRequest, err)
		return
	}
	data.PageCount = pageCount

	ctx.JSON(http.StatusOK, data)
}

// @Summary Get a specific path configuration
// @Tags config
// @Produce json
// @Param name path string true "Path name"
// @Success 200 {object} conf.Path
// @Failure 400 {object} defs.APIError
// @Failure 404 {object} defs.APIError
// @Router /v3/config/paths/get/{name} [get]
func (a *API) onConfigPathsGet(ctx *gin.Context) {
	confName, ok := paramName(ctx)
	if !ok {
		a.writeError(ctx, http.StatusBadRequest, fmt.Errorf("invalid name"))
		return
	}

	a.mutex.RLock()
	c := a.Conf
	a.mutex.RUnlock()

	p, ok := c.Paths[confName]
	if !ok {
		a.writeError(ctx, http.StatusNotFound, fmt.Errorf("path configuration not found"))
		return
	}

	ctx.JSON(http.StatusOK, p)
}

// @Summary Add a new path configuration
// @Tags config
// @Accept json
// @Produce json
// @Param name path string true "Path name"
// @Param config body conf.OptionalPath true "New path configuration"
// @Success 200
// @Failure 400 {object} defs.APIError
// @Router /v3/config/paths/add/{name} [post]
func (a *API) onConfigPathsAdd(ctx *gin.Context) { //nolint:dupl
	confName, ok := paramName(ctx)
	if !ok {
		a.writeError(ctx, http.StatusBadRequest, fmt.Errorf("invalid name"))
		return
	}

	var p conf.OptionalPath
	err := jsonwrapper.Decode(ctx.Request.Body, &p)
	if err != nil {
		a.writeError(ctx, http.StatusBadRequest, err)
		return
	}

	a.mutex.Lock()
	defer a.mutex.Unlock()

	newConf := a.Conf.Clone()

	err = newConf.AddPath(confName, &p)
	if err != nil {
		a.writeError(ctx, http.StatusBadRequest, err)
		return
	}

	err = newConf.Validate(nil)
	if err != nil {
		a.writeError(ctx, http.StatusBadRequest, err)
		return
	}

	a.Conf = newConf
	a.Parent.APIConfigSet(newConf)

	ctx.Status(http.StatusOK)
}

// @Summary Patch a specific path configuration
// @Tags config
// @Accept json
// @Produce json
// @Param name path string true "Path name"
// @Param config body conf.OptionalPath true "Path configuration patch"
// @Success 200
// @Failure 400 {object} defs.APIError
// @Failure 404 {object} defs.APIError
// @Router /v3/config/paths/patch/{name} [patch]
func (a *API) onConfigPathsPatch(ctx *gin.Context) { //nolint:dupl
	confName, ok := paramName(ctx)
	if !ok {
		a.writeError(ctx, http.StatusBadRequest, fmt.Errorf("invalid name"))
		return
	}

	var p conf.OptionalPath
	err := jsonwrapper.Decode(ctx.Request.Body, &p)
	if err != nil {
		a.writeError(ctx, http.StatusBadRequest, err)
		return
	}

	a.mutex.Lock()
	defer a.mutex.Unlock()

	newConf := a.Conf.Clone()

	err = newConf.PatchPath(confName, &p)
	if err != nil {
		if errors.Is(err, conf.ErrPathNotFound) {
			a.writeError(ctx, http.StatusNotFound, err)
		} else {
			a.writeError(ctx, http.StatusBadRequest, err)
		}
		return
	}

	err = newConf.Validate(nil)
	if err != nil {
		a.writeError(ctx, http.StatusBadRequest, err)
		return
	}

	a.Conf = newConf
	a.Parent.APIConfigSet(newConf)

	ctx.Status(http.StatusOK)
}

// @Summary Replace a specific path configuration
// @Tags config
// @Accept json
// @Produce json
// @Param name path string true "Path name"
// @Param config body conf.OptionalPath true "Full path configuration"
// @Success 200
// @Failure 400 {object} defs.APIError
// @Failure 404 {object} defs.APIError
// @Router /v3/config/paths/replace/{name} [post]
func (a *API) onConfigPathsReplace(ctx *gin.Context) { //nolint:dupl
	confName, ok := paramName(ctx)
	if !ok {
		a.writeError(ctx, http.StatusBadRequest, fmt.Errorf("invalid name"))
		return
	}

	var p conf.OptionalPath
	err := jsonwrapper.Decode(ctx.Request.Body, &p)
	if err != nil {
		a.writeError(ctx, http.StatusBadRequest, err)
		return
	}

	a.mutex.Lock()
	defer a.mutex.Unlock()

	newConf := a.Conf.Clone()

	err = newConf.ReplacePath(confName, &p)
	if err != nil {
		if errors.Is(err, conf.ErrPathNotFound) {
			a.writeError(ctx, http.StatusNotFound, err)
		} else {
			a.writeError(ctx, http.StatusBadRequest, err)
		}
		return
	}

	err = newConf.Validate(nil)
	if err != nil {
		a.writeError(ctx, http.StatusBadRequest, err)
		return
	}

	a.Conf = newConf
	a.Parent.APIConfigSet(newConf)

	ctx.Status(http.StatusOK)
}

// @Summary Delete a path configuration
// @Tags config
// @Produce json
// @Param name path string true "Path name"
// @Success 200
// @Failure 400 {object} defs.APIError
// @Failure 404 {object} defs.APIError
// @Router /v3/config/paths/delete/{name} [delete]
func (a *API) onConfigPathsDelete(ctx *gin.Context) {
	confName, ok := paramName(ctx)
	if !ok {
		a.writeError(ctx, http.StatusBadRequest, fmt.Errorf("invalid name"))
		return
	}

	a.mutex.Lock()
	defer a.mutex.Unlock()

	newConf := a.Conf.Clone()

	err := newConf.RemovePath(confName)
	if err != nil {
		if errors.Is(err, conf.ErrPathNotFound) {
			a.writeError(ctx, http.StatusNotFound, err)
		} else {
			a.writeError(ctx, http.StatusBadRequest, err)
		}
		return
	}

	err = newConf.Validate(nil)
	if err != nil {
		a.writeError(ctx, http.StatusBadRequest, err)
		return
	}

	a.Conf = newConf
	a.Parent.APIConfigSet(newConf)

	ctx.Status(http.StatusOK)
}

// @Summary Refresh JWKS public key cache
// @Tags auth
// @Success 200
// @Router /v3/auth/jwks/refresh [post]
func (a *API) onAuthJwksRefresh(ctx *gin.Context) {
	a.AuthManager.RefreshJWTJWKS()
	ctx.Status(http.StatusOK)
}

// @Summary List active stream paths
// @Tags runtime
// @Produce json
// @Param itemsPerPage query int false "Items per page"
// @Param page query int false "Page number"
// @Success 200 {object} defs.APIPathList
// @Failure 400 {object} defs.APIError
// @Failure 500 {object} defs.APIError
// @Router /v3/paths/list [get]
func (a *API) onPathsList(ctx *gin.Context) {
	data, err := a.PathManager.APIPathsList()
	if err != nil {
		a.writeError(ctx, http.StatusInternalServerError, err)
		return
	}

	data.ItemCount = len(data.Items)
	pageCount, err := paginate(&data.Items, ctx.Query("itemsPerPage"), ctx.Query("page"))
	if err != nil {
		a.writeError(ctx, http.StatusBadRequest, err)
		return
	}
	data.PageCount = pageCount

	ctx.JSON(http.StatusOK, data)
}

// @Summary Get stream details by path
// @Tags runtime
// @Produce json
// @Param name path string true "Path name"
// @Success 200 {object} defs.APIPath
// @Failure 400 {object} defs.APIError
// @Failure 404 {object} defs.APIError
// @Router /v3/paths/get/{name} [get]
func (a *API) onPathsGet(ctx *gin.Context) {
	pathName, ok := paramName(ctx)
	if !ok {
		a.writeError(ctx, http.StatusBadRequest, fmt.Errorf("invalid name"))
		return
	}

	data, err := a.PathManager.APIPathsGet(pathName)
	if err != nil {
		if errors.Is(err, conf.ErrPathNotFound) {
			a.writeError(ctx, http.StatusNotFound, err)
		} else {
			a.writeError(ctx, http.StatusInternalServerError, err)
		}
		return
	}

	ctx.JSON(http.StatusOK, data)
}

// onRTSPConnsList lists all active RTSP connections.
//
// @Summary List RTSP connections
// @Tags rtsp
// @Produce json
// @Param itemsPerPage query int false "Number of items per page"
// @Param page query int false "Page number"
// @Success 200 {object} defs.APIRTSPConnsList
// @Failure 400 {object} defs.APIError
// @Failure 500 {object} defs.APIError
// @Router /v3/rtspconns/list [get]
func (a *API) onRTSPConnsList(ctx *gin.Context) {
	data, err := a.RTSPServer.APIConnsList()
	if err != nil {
		a.writeError(ctx, http.StatusInternalServerError, err)
		return
	}

	data.ItemCount = len(data.Items)
	pageCount, err := paginate(&data.Items, ctx.Query("itemsPerPage"), ctx.Query("page"))
	if err != nil {
		a.writeError(ctx, http.StatusBadRequest, err)
		return
	}
	data.PageCount = pageCount

	ctx.JSON(http.StatusOK, data)
}

// @Summary Get RTSP connection details by ID
// @Tags rtsp
// @Produce json
// @Param id path string true "Connection UUID"
// @Success 200 {object} defs.APIRTSPConn
// @Failure 400 {object} defs.APIError
// @Failure 404 {object} defs.APIError
// @Router /v3/rtspconns/get/{id} [get]
func (a *API) onRTSPConnsGet(ctx *gin.Context) {
	uuid, err := uuid.Parse(ctx.Param("id"))
	if err != nil {
		a.writeError(ctx, http.StatusBadRequest, err)
		return
	}

	data, err := a.RTSPServer.APIConnsGet(uuid)
	if err != nil {
		if errors.Is(err, rtsp.ErrConnNotFound) {
			a.writeError(ctx, http.StatusNotFound, err)
		} else {
			a.writeError(ctx, http.StatusInternalServerError, err)
		}
		return
	}

	ctx.JSON(http.StatusOK, data)
}

// onRTSPSessionsList lists all RTSP sessions.
//
// @Summary List RTSP sessions
// @Tags rtsp
// @Produce json
// @Success 200 {object} defs.APIRTSPSessionList
// @Failure 500 {object} defs.APIError
// @Router /v3/rtspsessions/list [get]
func (a *API) onRTSPSessionsList(ctx *gin.Context) {
	data, err := a.RTSPServer.APISessionsList()
	if err != nil {
		a.writeError(ctx, http.StatusInternalServerError, err)
		return
	}

	data.ItemCount = len(data.Items)
	pageCount, err := paginate(&data.Items, ctx.Query("itemsPerPage"), ctx.Query("page"))
	if err != nil {
		a.writeError(ctx, http.StatusBadRequest, err)
		return
	}
	data.PageCount = pageCount

	ctx.JSON(http.StatusOK, data)
}

// onRTSPSessionsGet retrieves an RTSP session by ID.
//
// @Summary Get RTSP session
// @Tags rtsp
// @Produce json
// @Param id path string true "Session UUID"
// @Success 200 {object} defs.APIRTSPSession
// @Failure 400 {object} defs.APIError
// @Failure 404 {object} defs.APIError
// @Router /v3/rtspsessions/get/{id} [get]
func (a *API) onRTSPSessionsGet(ctx *gin.Context) {
	uuid, err := uuid.Parse(ctx.Param("id"))
	if err != nil {
		a.writeError(ctx, http.StatusBadRequest, err)
		return
	}

	data, err := a.RTSPServer.APISessionsGet(uuid)
	if err != nil {
		if errors.Is(err, rtsp.ErrSessionNotFound) {
			a.writeError(ctx, http.StatusNotFound, err)
		} else {
			a.writeError(ctx, http.StatusInternalServerError, err)
		}
		return
	}

	ctx.JSON(http.StatusOK, data)
}

// onRTSPSessionsKick terminates an RTSP session by ID.
//
// @Summary Kick RTSP session
// @Tags rtsp
// @Param id path string true "Session UUID"
// @Success 200
// @Failure 400 {object} defs.APIError
// @Failure 404 {object} defs.APIError
// @Router /v3/rtspsessions/kick/{id} [post]
func (a *API) onRTSPSessionsKick(ctx *gin.Context) {
	uuid, err := uuid.Parse(ctx.Param("id"))
	if err != nil {
		a.writeError(ctx, http.StatusBadRequest, err)
		return
	}

	err = a.RTSPServer.APISessionsKick(uuid)
	if err != nil {
		if errors.Is(err, rtsp.ErrSessionNotFound) {
			a.writeError(ctx, http.StatusNotFound, err)
		} else {
			a.writeError(ctx, http.StatusInternalServerError, err)
		}
		return
	}

	ctx.Status(http.StatusOK)
}

// onRTSPSConnsList lists all RTSPS (RTSP over TLS) connections.
//
// @Summary List RTSPS connections
// @Tags rtsps
// @Produce json
// @Success 200 {object} defs.APIRTSPConnsList
// @Failure 500 {object} defs.APIError
// @Router /v3/rtspsconns/list [get]
func (a *API) onRTSPSConnsList(ctx *gin.Context) {
	data, err := a.RTSPSServer.APIConnsList()
	if err != nil {
		a.writeError(ctx, http.StatusInternalServerError, err)
		return
	}

	data.ItemCount = len(data.Items)
	pageCount, err := paginate(&data.Items, ctx.Query("itemsPerPage"), ctx.Query("page"))
	if err != nil {
		a.writeError(ctx, http.StatusBadRequest, err)
		return
	}
	data.PageCount = pageCount

	ctx.JSON(http.StatusOK, data)
}

// onRTSPSConnsGet gets a specific RTSPS connection.
//
// @Summary Get RTSPS connection
// @Tags rtsps
// @Produce json
// @Param id path string true "Connection UUID"
// @Success 200 {object} defs.APIRTSPConn
// @Failure 400 {object} defs.APIError
// @Failure 404 {object} defs.APIError
// @Router /v3/rtspsconns/get/{id} [get]
func (a *API) onRTSPSConnsGet(ctx *gin.Context) {
	uuid, err := uuid.Parse(ctx.Param("id"))
	if err != nil {
		a.writeError(ctx, http.StatusBadRequest, err)
		return
	}

	data, err := a.RTSPSServer.APIConnsGet(uuid)
	if err != nil {
		if errors.Is(err, rtsp.ErrConnNotFound) {
			a.writeError(ctx, http.StatusNotFound, err)
		} else {
			a.writeError(ctx, http.StatusInternalServerError, err)
		}
		return
	}

	ctx.JSON(http.StatusOK, data)
}

// onRTSPSSessionsList lists all RTSPS sessions.
//
// @Summary List RTSPS sessions
// @Tags rtsps
// @Produce json
// @Success 200 {object} defs.APIRTSPSessionList
// @Failure 500 {object} defs.APIError
// @Router /v3/rtspssessions/list [get]
func (a *API) onRTSPSSessionsList(ctx *gin.Context) {
	data, err := a.RTSPSServer.APISessionsList()
	if err != nil {
		a.writeError(ctx, http.StatusInternalServerError, err)
		return
	}

	data.ItemCount = len(data.Items)
	pageCount, err := paginate(&data.Items, ctx.Query("itemsPerPage"), ctx.Query("page"))
	if err != nil {
		a.writeError(ctx, http.StatusBadRequest, err)
		return
	}
	data.PageCount = pageCount

	ctx.JSON(http.StatusOK, data)
}

// onRTSPSSessionsGet gets a specific RTSPS session.
//
// @Summary Get RTSPS session
// @Tags rtsps
// @Produce json
// @Param id path string true "Session UUID"
// @Success 200 {object} defs.APIRTSPSession
// @Failure 400 {object} defs.APIError
// @Failure 404 {object} defs.APIError
// @Router /v3/rtspssessions/get/{id} [get]
func (a *API) onRTSPSSessionsGet(ctx *gin.Context) {
	uuid, err := uuid.Parse(ctx.Param("id"))
	if err != nil {
		a.writeError(ctx, http.StatusBadRequest, err)
		return
	}

	data, err := a.RTSPSServer.APISessionsGet(uuid)
	if err != nil {
		if errors.Is(err, rtsp.ErrSessionNotFound) {
			a.writeError(ctx, http.StatusNotFound, err)
		} else {
			a.writeError(ctx, http.StatusInternalServerError, err)
		}
		return
	}

	ctx.JSON(http.StatusOK, data)
}

// onRTSPSSessionsKick forcibly disconnects a RTSPS session.
//
// @Summary Kick RTSPS session
// @Tags rtsps
// @Param id path string true "Session UUID"
// @Success 200
// @Failure 400 {object} defs.APIError
// @Failure 404 {object} defs.APIError
// @Router /v3/rtspssessions/kick/{id} [post]
func (a *API) onRTSPSSessionsKick(ctx *gin.Context) {
	uuid, err := uuid.Parse(ctx.Param("id"))
	if err != nil {
		a.writeError(ctx, http.StatusBadRequest, err)
		return
	}

	err = a.RTSPSServer.APISessionsKick(uuid)
	if err != nil {
		if errors.Is(err, rtsp.ErrSessionNotFound) {
			a.writeError(ctx, http.StatusNotFound, err)
		} else {
			a.writeError(ctx, http.StatusInternalServerError, err)
		}
		return
	}

	ctx.Status(http.StatusOK)
}

// onRTMPConnsList lists all RTMP connections.
//
// @Summary List RTMP connections
// @Tags rtmp
// @Produce json
// @Success 200 {object} defs.APIRTMPConnList
// @Failure 500 {object} defs.APIError
// @Router /v3/rtmpconns/list [get]
func (a *API) onRTMPConnsList(ctx *gin.Context) {
	data, err := a.RTMPServer.APIConnsList()
	if err != nil {
		a.writeError(ctx, http.StatusInternalServerError, err)
		return
	}

	data.ItemCount = len(data.Items)
	pageCount, err := paginate(&data.Items, ctx.Query("itemsPerPage"), ctx.Query("page"))
	if err != nil {
		a.writeError(ctx, http.StatusBadRequest, err)
		return
	}
	data.PageCount = pageCount

	ctx.JSON(http.StatusOK, data)
}

// onRTMPConnsGet gets a specific RTMP connection.
//
// @Summary Get RTMP connection
// @Tags rtmp
// @Produce json
// @Param id path string true "Connection UUID"
// @Success 200 {object} defs.APIRTMPConn
// @Failure 400 {object} defs.APIError
// @Failure 404 {object} defs.APIError
// @Router /v3/rtmpconns/get/{id} [get]
func (a *API) onRTMPConnsGet(ctx *gin.Context) {
	uuid, err := uuid.Parse(ctx.Param("id"))
	if err != nil {
		a.writeError(ctx, http.StatusBadRequest, err)
		return
	}

	data, err := a.RTMPServer.APIConnsGet(uuid)
	if err != nil {
		if errors.Is(err, rtmp.ErrConnNotFound) {
			a.writeError(ctx, http.StatusNotFound, err)
		} else {
			a.writeError(ctx, http.StatusInternalServerError, err)
		}
		return
	}

	ctx.JSON(http.StatusOK, data)
}

// onRTMPConnsKick forcibly disconnects a RTMP connection.
//
// @Summary Kick RTMP connection
// @Tags rtmp
// @Param id path string true "Connection UUID"
// @Success 200
// @Failure 400 {object} defs.APIError
// @Failure 404 {object} defs.APIError
// @Router /v3/rtmpconns/kick/{id} [post]
func (a *API) onRTMPConnsKick(ctx *gin.Context) {
	uuid, err := uuid.Parse(ctx.Param("id"))
	if err != nil {
		a.writeError(ctx, http.StatusBadRequest, err)
		return
	}

	err = a.RTMPServer.APIConnsKick(uuid)
	if err != nil {
		if errors.Is(err, rtmp.ErrConnNotFound) {
			a.writeError(ctx, http.StatusNotFound, err)
		} else {
			a.writeError(ctx, http.StatusInternalServerError, err)
		}
		return
	}

	ctx.Status(http.StatusOK)
}

// onRTMPSConnsList lists all RTMPS (RTMP over TLS) connections.
//
// @Summary List RTMPS connections
// @Tags rtmps
// @Produce json
// @Success 200 {object} defs.APIRTMPConnList
// @Failure 500 {object} defs.APIError
// @Router /v3/rtmpsconns/list [get]
func (a *API) onRTMPSConnsList(ctx *gin.Context) {
	data, err := a.RTMPSServer.APIConnsList()
	if err != nil {
		a.writeError(ctx, http.StatusInternalServerError, err)
		return
	}

	data.ItemCount = len(data.Items)
	pageCount, err := paginate(&data.Items, ctx.Query("itemsPerPage"), ctx.Query("page"))
	if err != nil {
		a.writeError(ctx, http.StatusBadRequest, err)
		return
	}
	data.PageCount = pageCount

	ctx.JSON(http.StatusOK, data)
}

// onRTMPSConnsGet gets a specific RTMPS connection.
//
// @Summary Get RTMPS connection
// @Tags rtmps
// @Produce json
// @Param id path string true "Connection UUID"
// @Success 200 {object} defs.APIRTMPConn
// @Failure 400 {object} defs.APIError
// @Failure 404 {object} defs.APIError
// @Router /v3/rtmpsconns/get/{id} [get]
func (a *API) onRTMPSConnsGet(ctx *gin.Context) {
	uuid, err := uuid.Parse(ctx.Param("id"))
	if err != nil {
		a.writeError(ctx, http.StatusBadRequest, err)
		return
	}

	data, err := a.RTMPSServer.APIConnsGet(uuid)
	if err != nil {
		if errors.Is(err, rtmp.ErrConnNotFound) {
			a.writeError(ctx, http.StatusNotFound, err)
		} else {
			a.writeError(ctx, http.StatusInternalServerError, err)
		}
		return
	}

	ctx.JSON(http.StatusOK, data)
}

// onRTMPSConnsKick forcibly closes an RTMPS connection by ID.
//
// @Summary Kick RTMPS connection
// @Tags rtmps
// @Param id path string true "Connection ID"
// @Success 200 {string} string "OK"
// @Failure 400 {object} defs.APIError
// @Failure 404 {object} defs.APIError
// @Router /v3/rtmpsconns/kick/{id} [post]
func (a *API) onRTMPSConnsKick(ctx *gin.Context) {
	uuid, err := uuid.Parse(ctx.Param("id"))
	if err != nil {
		a.writeError(ctx, http.StatusBadRequest, err)
		return
	}

	err = a.RTMPSServer.APIConnsKick(uuid)
	if err != nil {
		if errors.Is(err, rtmp.ErrConnNotFound) {
			a.writeError(ctx, http.StatusNotFound, err)
		} else {
			a.writeError(ctx, http.StatusInternalServerError, err)
		}
		return
	}

	ctx.Status(http.StatusOK)
}

// onHLSMuxersList lists active HLS muxers.
//
// @Summary List HLS muxers
// @Tags hls
// @Produce json
// @Success 200 {object} defs.APIHLSMuxerList
// @Failure 500 {object} defs.APIError
// @Router /v3/hlsmuxers/list [get]
func (a *API) onHLSMuxersList(ctx *gin.Context) {
	data, err := a.HLSServer.APIMuxersList()
	if err != nil {
		a.writeError(ctx, http.StatusInternalServerError, err)
		return
	}

	data.ItemCount = len(data.Items)
	pageCount, err := paginate(&data.Items, ctx.Query("itemsPerPage"), ctx.Query("page"))
	if err != nil {
		a.writeError(ctx, http.StatusBadRequest, err)
		return
	}
	data.PageCount = pageCount

	ctx.JSON(http.StatusOK, data)
}

// onHLSMuxersGet retrieves an HLS muxer by path.
//
// @Summary Get HLS muxer
// @Tags hls
// @Produce json
// @Param name path string true "Path name"
// @Success 200 {object} defs.APIHLSMuxer
// @Failure 400 {object} defs.APIError
// @Failure 404 {object} defs.APIError
// @Router /v3/hlsmuxers/get/{name} [get]
func (a *API) onHLSMuxersGet(ctx *gin.Context) {
	pathName, ok := paramName(ctx)
	if !ok {
		a.writeError(ctx, http.StatusBadRequest, fmt.Errorf("invalid name"))
		return
	}

	data, err := a.HLSServer.APIMuxersGet(pathName)
	if err != nil {
		if errors.Is(err, hls.ErrMuxerNotFound) {
			a.writeError(ctx, http.StatusNotFound, err)
		} else {
			a.writeError(ctx, http.StatusInternalServerError, err)
		}
		return
	}

	ctx.JSON(http.StatusOK, data)
}

// onWebRTCSessionsList lists WebRTC sessions.
//
// @Summary List WebRTC sessions
// @Tags webrtc
// @Produce json
// @Success 200 {object} defs.APIWebRTCSessionList
// @Failure 500 {object} defs.APIError
// @Router /v3/webrtcsessions/list [get]
func (a *API) onWebRTCSessionsList(ctx *gin.Context) {
	data, err := a.WebRTCServer.APISessionsList()
	if err != nil {
		a.writeError(ctx, http.StatusInternalServerError, err)
		return
	}

	data.ItemCount = len(data.Items)
	pageCount, err := paginate(&data.Items, ctx.Query("itemsPerPage"), ctx.Query("page"))
	if err != nil {
		a.writeError(ctx, http.StatusBadRequest, err)
		return
	}
	data.PageCount = pageCount

	ctx.JSON(http.StatusOK, data)
}

// onWebRTCSessionsGet retrieves a WebRTC session by ID.
//
// @Summary Get WebRTC session
// @Tags webrtc
// @Produce json
// @Param id path string true "Session ID"
// @Success 200 {object} defs.APIWebRTCSession
// @Failure 400 {object} defs.APIError
// @Failure 404 {object} defs.APIError
// @Router /v3/webrtcsessions/get/{id} [get]
func (a *API) onWebRTCSessionsGet(ctx *gin.Context) {
	uuid, err := uuid.Parse(ctx.Param("id"))
	if err != nil {
		a.writeError(ctx, http.StatusBadRequest, err)
		return
	}

	data, err := a.WebRTCServer.APISessionsGet(uuid)
	if err != nil {
		if errors.Is(err, webrtc.ErrSessionNotFound) {
			a.writeError(ctx, http.StatusNotFound, err)
		} else {
			a.writeError(ctx, http.StatusInternalServerError, err)
		}
		return
	}

	ctx.JSON(http.StatusOK, data)
}

// onWebRTCSessionsKick forcibly closes a WebRTC session.
//
// @Summary Kick WebRTC session
// @Tags webrtc
// @Param id path string true "Session ID"
// @Success 200 {string} string "OK"
// @Failure 400 {object} defs.APIError
// @Failure 404 {object} defs.APIError
// @Router /v3/webrtcsessions/kick/{id} [post]
func (a *API) onWebRTCSessionsKick(ctx *gin.Context) {
	uuid, err := uuid.Parse(ctx.Param("id"))
	if err != nil {
		a.writeError(ctx, http.StatusBadRequest, err)
		return
	}

	err = a.WebRTCServer.APISessionsKick(uuid)
	if err != nil {
		if errors.Is(err, webrtc.ErrSessionNotFound) {
			a.writeError(ctx, http.StatusNotFound, err)
		} else {
			a.writeError(ctx, http.StatusInternalServerError, err)
		}
		return
	}

	ctx.Status(http.StatusOK)
}

// onSRTConnsList lists SRT connections.
//
// @Summary List SRT connections
// @Tags srt
// @Produce json
// @Success 200 {object} defs.APISRTConnList
// @Failure 500 {object} defs.APIError
// @Router /v3/srtconns/list [get]
func (a *API) onSRTConnsList(ctx *gin.Context) {
	data, err := a.SRTServer.APIConnsList()
	if err != nil {
		a.writeError(ctx, http.StatusInternalServerError, err)
		return
	}

	data.ItemCount = len(data.Items)
	pageCount, err := paginate(&data.Items, ctx.Query("itemsPerPage"), ctx.Query("page"))
	if err != nil {
		a.writeError(ctx, http.StatusBadRequest, err)
		return
	}
	data.PageCount = pageCount

	ctx.JSON(http.StatusOK, data)
}

// onSRTConnsGet gets a specific SRT connection.
//
// @Summary Get SRT connection
// @Tags srt
// @Produce json
// @Param id path string true "Connection ID"
// @Success 200 {object} defs.APISRTConn
// @Failure 400 {object} defs.APIError
// @Failure 404 {object} defs.APIError
// @Router /v3/srtconns/get/{id} [get]
func (a *API) onSRTConnsGet(ctx *gin.Context) {
	uuid, err := uuid.Parse(ctx.Param("id"))
	if err != nil {
		a.writeError(ctx, http.StatusBadRequest, err)
		return
	}

	data, err := a.SRTServer.APIConnsGet(uuid)
	if err != nil {
		if errors.Is(err, srt.ErrConnNotFound) {
			a.writeError(ctx, http.StatusNotFound, err)
		} else {
			a.writeError(ctx, http.StatusInternalServerError, err)
		}
		return
	}

	ctx.JSON(http.StatusOK, data)
}

// onSRTConnsKick kicks a specific SRT connection.
//
// @Summary Kick SRT connection
// @Tags srt
// @Param id path string true "Connection ID"
// @Success 200 {string} string "OK"
// @Failure 400 {object} defs.APIError
// @Failure 404 {object} defs.APIError
// @Router /v3/srtconns/kick/{id} [post]
func (a *API) onSRTConnsKick(ctx *gin.Context) {
	uuid, err := uuid.Parse(ctx.Param("id"))
	if err != nil {
		a.writeError(ctx, http.StatusBadRequest, err)
		return
	}

	err = a.SRTServer.APIConnsKick(uuid)
	if err != nil {
		if errors.Is(err, srt.ErrConnNotFound) {
			a.writeError(ctx, http.StatusNotFound, err)
		} else {
			a.writeError(ctx, http.StatusInternalServerError, err)
		}
		return
	}

	ctx.Status(http.StatusOK)
}

// onRecordingsList lists recordings by path.
//
// @Summary List recordings
// @Tags recordings
// @Produce json
// @Success 200 {object} defs.APIRecordingList
// @Failure 400 {object} defs.APIError
// @Router /v3/recordings/list [get]
func (a *API) onRecordingsList(ctx *gin.Context) {
	a.mutex.RLock()
	c := a.Conf
	a.mutex.RUnlock()

	pathNames := recordstore.FindAllPathsWithSegments(c.Paths)

	data := defs.APIRecordingList{}

	data.ItemCount = len(pathNames)
	pageCount, err := paginate(&pathNames, ctx.Query("itemsPerPage"), ctx.Query("page"))
	if err != nil {
		a.writeError(ctx, http.StatusBadRequest, err)
		return
	}
	data.PageCount = pageCount

	data.Items = make([]*defs.APIRecording, len(pathNames))

	for i, pathName := range pathNames {
		pathConf, _, _ := conf.FindPathConf(c.Paths, pathName)
		data.Items[i] = recordingsOfPath(pathConf, pathName)
	}

	ctx.JSON(http.StatusOK, data)
}

// onRecordingsGet gets recordings by path name.
//
// @Summary Get recordings
// @Tags recordings
// @Produce json
// @Param name path string true "Path name"
// @Success 200 {object} defs.APIRecording
// @Failure 400 {object} defs.APIError
// @Failure 404 {object} defs.APIError
// @Router /v3/recordings/get/{name} [get]
func (a *API) onRecordingsGet(ctx *gin.Context) {
	pathName, ok := paramName(ctx)
	if !ok {
		a.writeError(ctx, http.StatusBadRequest, fmt.Errorf("invalid name"))
		return
	}

	a.mutex.RLock()
	c := a.Conf
	a.mutex.RUnlock()

	pathConf, _, err := conf.FindPathConf(c.Paths, pathName)
	if err != nil {
		a.writeError(ctx, http.StatusBadRequest, err)
		return
	}

	ctx.JSON(http.StatusOK, recordingsOfPath(pathConf, pathName))
}

// onRecordingDeleteSegment deletes a recording segment.
//
// @Summary Delete a recording segment
// @Tags recordings
// @Param path query string true "Path name"
// @Param start query string true "Start time (RFC3339)"
// @Success 200 {string} string "OK"
// @Failure 400 {object} defs.APIError
// @Router /v3/recordings/deletesegment [delete]
func (a *API) onRecordingDeleteSegment(ctx *gin.Context) {
	pathName := ctx.Query("path")

	start, err := time.Parse(time.RFC3339, ctx.Query("start"))
	if err != nil {
		a.writeError(ctx, http.StatusBadRequest, fmt.Errorf("invalid 'start' parameter: %w", err))
		return
	}

	a.mutex.RLock()
	c := a.Conf
	a.mutex.RUnlock()

	pathConf, _, err := conf.FindPathConf(c.Paths, pathName)
	if err != nil {
		a.writeError(ctx, http.StatusBadRequest, err)
		return
	}

	pathFormat := recordstore.PathAddExtension(
		strings.ReplaceAll(pathConf.RecordPath, "%path", pathName),
		pathConf.RecordFormat,
	)

	segmentPath := recordstore.Path{
		Start: start,
	}.Encode(pathFormat)

	err = os.Remove(segmentPath)
	if err != nil {
		a.writeError(ctx, http.StatusBadRequest, err)
		return
	}

	ctx.Status(http.StatusOK)
}

// ReloadConf is called by core.
func (a *API) ReloadConf(conf *conf.Conf) {
	a.mutex.Lock()
	defer a.mutex.Unlock()
	a.Conf = conf
}
