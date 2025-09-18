package main

import (
	"context"
	"crypto/sha256"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"crypto/pbkdf2"

	proto "go.sia.tech/core/rhp/v4"
	"go.sia.tech/core/types"
	"go.sia.tech/coreutils/wallet"
	"go.sia.tech/indexd/api/app"
	"go.sia.tech/indexd/sdk"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"lukechampine.com/frand"
)

const (
	statsInterval = time.Minute
	statsAlpha    = 0.3 // EMA smoothing factor
)

type config struct {
	appSecret     string
	indexerURL    string
	redundancyStr string

	logLevel zap.AtomicLevel
	logPath  string

	threads     int
	slabs       int
	hostTimeout time.Duration
}

var (
	// derived from flags (defaults here as fallbacks)
	dataShards   uint8 = 2
	parityShards uint8 = 4

	throughput atomic.Int64 // bytes uploaded (redundant) since last tick
	ema        float64      // mbps EMA (written only by stats goroutine)
)

func main() {
	cfg := parseFlags()

	log, err := newLogger(cfg.logLevel, cfg.logPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to init logger: %v\n", err)
		os.Exit(1)
	}
	defer func() { _ = log.Sync() }()

	sk, err := loadPrivateKey(cfg.appSecret)
	if err != nil {
		log.Fatal("failed to load private key", zap.Error(err))
	}

	if err := parseRedundancy(cfg.redundancyStr); err != nil {
		log.Fatal("failed to parse redundancy", zap.Error(err))
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	resp, connected, err := sdk.Connect(ctx, cfg.indexerURL, sk, app.RegisterAppRequest{
		Name:        "junkd Uploader",
		Description: "A tool to upload junk data to the indexer",
		LogoURL:     "https://example.com/logo.png",
		ServiceURL:  "https://example.com/service",
	})
	if err != nil {
		log.Fatal("failed to connect app", zap.Error(err))
	} else if !connected {
		log.Info("please approve app connection", zap.String("url", resp.ResponseURL))
		connected, err := resp.WaitForApproval(ctx)
		if err != nil {
			log.Fatal("failed to wait for app approval", zap.Error(err))
		}
		if !connected {
			log.Fatal("user denied app connection")
		}
	}

	redundantSizePerBatch := int64((dataShards + parityShards)) * proto.SectorSize * int64(cfg.slabs)
	dataSizePerBatch := int64(dataShards) * proto.SectorSize * int64(cfg.slabs)

	log.Info("junkd connected",
		zap.String("redundancy", fmt.Sprintf("%d-%d", dataShards, parityShards)),
		zap.String("slab_size", humanReadableSize(int64(dataShards)*proto.SectorSize)),
		zap.String("upload_size", humanReadableSize(dataSizePerBatch)),
		zap.String("redundant_size", humanReadableSize(redundantSizePerBatch)),
		zap.Duration("host_timeout", cfg.hostTimeout),
	)

	sdkClient, err := sdk.NewSDK(cfg.indexerURL, sk, sdk.WithLogger(log.Named("sdk")))
	if err != nil {
		log.Fatal("failed to create SDK client", zap.Error(err))
	}

	// stats goroutine
	go printUploadSpeed(ctx, log)

	// upload workers
	var wg sync.WaitGroup
	for n := 1; n <= cfg.threads; n++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			workerLog := log.Named(fmt.Sprintf("upload-thread-%d", n))
			workerLog.Debug("starting upload thread")
			uploadWorker(ctx, sdkClient, workerLog, dataSizePerBatch, redundantSizePerBatch, cfg.hostTimeout)
			workerLog.Debug("shutting down upload thread")
		}(n)
	}
	wg.Wait()

	log.Info("all upload threads finished, exiting")
}

func uploadWorker(ctx context.Context, sdkClient *sdk.SDK, log *zap.Logger, dataSizePerBatch, redundantSizePerBatch int64, hostTimeout time.Duration) {
	retryDelay := 5 * time.Minute

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		start := time.Now()
		r := io.LimitReader(frand.Reader, dataSizePerBatch)

		_, err := sdkClient.Upload(
			ctx,
			r,
			sdk.WithRedundancy(dataShards, parityShards),
			sdk.WithUploadHostTimeout(hostTimeout),
		)

		switch {
		case err == nil:
			throughput.Add(redundantSizePerBatch)
			log.Info("upload completed", zap.Duration("duration", time.Since(start)))
		case errors.Is(err, context.Canceled):
			return
		default:
			log.Error("failed to upload slab; backing off", zap.Error(err), zap.Duration("duration", time.Since(start)), zap.Duration("backoff", retryDelay))
			timer := time.NewTimer(retryDelay)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
				// retry
			}
		}
	}
}

func printUploadSpeed(ctx context.Context, log *zap.Logger) {
	ticker := time.NewTicker(statsInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			uploaded := throughput.Swap(0) // bytes in the last interval
			seconds := statsInterval.Seconds()
			mbps := (float64(uploaded) * 8) / 1_000_000 / seconds

			if ema == 0 {
				ema = mbps
			} else {
				ema = statsAlpha*mbps + (1-statsAlpha)*ema
			}

			log.Info("upload speed",
				zap.Float64("mbps_instant", mbps),
				zap.Float64("mbps_ema", ema),
			)
		}
	}
}

func loadPrivateKey(appSecret string) (types.PrivateKey, error) {
	if appSecret == "" {
		return types.PrivateKey{}, fmt.Errorf("app secret is required")
	}
	derived, err := pbkdf2.Key(sha256.New, appSecret, []byte("junkd-pk-salt"), 4096, 32)
	if err != nil {
		return types.PrivateKey{}, fmt.Errorf("failed to derive key: %w", err)
	}
	var seed [32]byte
	copy(seed[:], derived)
	return wallet.KeyFromSeed(&seed, 0), nil
}

func parseRedundancy(s string) error {
	if strings.TrimSpace(s) == "" {
		// keep defaults
		return nil
	}
	a, b, ok := strings.Cut(s, "-")
	if !ok {
		return fmt.Errorf("expected format 'data-parity', got %q", s)
	}
	ad, err := strconv.Atoi(a)
	if err != nil {
		return fmt.Errorf("invalid data shards: %w", err)
	}
	pd, err := strconv.Atoi(b)
	if err != nil {
		return fmt.Errorf("invalid parity shards: %w", err)
	}
	if ad < 1 || pd < 1 || ad*3 < ad+pd {
		return fmt.Errorf("invalid redundancy configuration: %d-%d", ad, pd)
	}
	dataShards, parityShards = uint8(ad), uint8(pd)
	return nil
}

func newLogger(level zap.AtomicLevel, path string) (*zap.Logger, error) {
	encCfg := zap.NewProductionEncoderConfig()
	encCfg.EncodeTime = zapcore.ISO8601TimeEncoder
	encCfg.EncodeDuration = zapcore.MillisDurationEncoder
	encCfg.EncodeLevel = zapcore.CapitalColorLevelEncoder // colorized console

	console := zapcore.NewCore(
		zapcore.NewConsoleEncoder(encCfg),
		zapcore.AddSync(zapcore.Lock(os.Stdout)),
		level,
	)

	if strings.TrimSpace(path) == "" {
		return zap.New(console), nil
	}

	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, err
	}
	fileCore := zapcore.NewCore(
		zapcore.NewJSONEncoder(encCfg),
		zapcore.AddSync(f),
		level,
	)

	return zap.New(zapcore.NewTee(console, fileCore)), nil
}

func humanReadableSize(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

func parseFlags() config {
	var cfg config
	flag.StringVar(&cfg.indexerURL, "indexer.url", "http://localhost:9982", "the URL of the indexer API")
	flag.StringVar(&cfg.appSecret, "app.secret", "", "a secret used to derive the application key")
	flag.TextVar(&cfg.logLevel, "log.level", zap.NewAtomicLevelAt(zap.InfoLevel), "the log level to use")
	flag.StringVar(&cfg.logPath, "log.path", "", "the path to write the log to")
	flag.IntVar(&cfg.threads, "threads", 1, "the number of upload threads")
	flag.IntVar(&cfg.slabs, "slabs", 1, "the number of slabs to upload")
	flag.StringVar(&cfg.redundancyStr, "redundancy", "10-20", "the redundancy configuration, in the form data-parity (e.g. 10-20 for 10 data and 20 parity shards)")
	flag.DurationVar(&cfg.hostTimeout, "host.timeout", 10*time.Second, "the amount of time until we timeout a host during upload")
	flag.Parse()
	return cfg
}
