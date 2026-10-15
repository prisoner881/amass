// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package pubsub

import (
	"runtime"
	"strconv"
	"testing"
	"time"
)

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestLoggerDeliversInOrder(t *testing.T) {
	l := NewLogger()
	defer l.Close()
	ch := l.Subscribe()

	const n = 500
	for i := 0; i < n; i++ {
		l.Publish(strconv.Itoa(i))
	}
	for i := 0; i < n; i++ {
		select {
		case msg := <-ch:
			if *msg != strconv.Itoa(i) {
				t.Fatalf("message %d: got %q", i, *msg)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("timed out at message %d", i)
		}
	}
}

func TestLoggerUnsubscribeClosesChannel(t *testing.T) {
	l := NewLogger()
	defer l.Close()
	ch := l.Subscribe()
	if l.Subscribers() != 1 {
		t.Fatalf("got %d subscribers, want 1", l.Subscribers())
	}

	l.Unsubscribe(ch)
	l.Unsubscribe(ch) // a second call is harmless
	if l.Subscribers() != 0 {
		t.Fatalf("got %d subscribers after Unsubscribe, want 0", l.Subscribers())
	}
	waitFor(t, "the channel to close", func() bool {
		select {
		case _, ok := <-ch:
			return !ok
		default:
			return false
		}
	})
}

// A subscriber that stops reading must not leave goroutines behind once it is
// unsubscribed. The old implementation started a goroutine per message once a
// subscriber's buffer was full, and they blocked forever.
func TestLoggerStalledSubscriberLeaksNothing(t *testing.T) {
	l := NewLogger()
	defer l.Close()
	runtime.GC()
	before := runtime.NumGoroutine()

	ch := l.Subscribe() // never read
	for i := 0; i < 5000; i++ {
		l.Publish(strconv.Itoa(i))
	}
	waitFor(t, "the messages to be queued", func() bool { return l.q.Empty() })
	if during := runtime.NumGoroutine(); during > before+5 {
		t.Fatalf("%d goroutines while a subscriber is stalled, started with %d", during, before)
	}

	l.Unsubscribe(ch)
	waitFor(t, "the subscriber's goroutine to exit", func() bool {
		return runtime.NumGoroutine() <= before
	})
}

// Close used to close subscriber channels while sends to them could still be
// pending, which panics. With a stalled subscriber that must not happen.
func TestLoggerCloseWithStalledSubscriber(t *testing.T) {
	l := NewLogger()
	ch := l.Subscribe() // never read
	for i := 0; i < 1000; i++ {
		l.Publish(strconv.Itoa(i))
	}
	waitFor(t, "the messages to be queued", func() bool { return l.q.Empty() })

	l.Close()
	l.Close() // a second call is harmless
	waitFor(t, "the channel to close", func() bool {
		for {
			select {
			case _, ok := <-ch:
				if !ok {
					return true
				}
			default:
				return false
			}
		}
	})
}

func TestLoggerSubscribeAfterClose(t *testing.T) {
	l := NewLogger()
	l.Close()

	ch := l.Subscribe()
	if _, ok := <-ch; ok {
		t.Fatal("subscribing to a closed logger should return a closed channel")
	}
	l.Publish("ignored")
	l.Unsubscribe(ch)
}

func TestLoggerPublishWithoutSubscribersIsDropped(t *testing.T) {
	l := NewLogger()
	defer l.Close()

	l.Publish("before")
	ch := l.Subscribe()
	l.Publish("after")

	select {
	case msg := <-ch:
		if *msg != "after" {
			t.Fatalf("got %q, want only the message published after subscribing", *msg)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out")
	}
}
