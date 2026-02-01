package api

import (
	"sync/atomic"
)

var warmupCompleted atomic.Bool

func IsWarmupCompleted() bool {
	return warmupCompleted.Load()
}

func SetWarmupCompleted() {
	warmupCompleted.Store(true)
}
