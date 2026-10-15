// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package pubsub

import (
	"sync"
	"sync/atomic"

	"github.com/caffix/queue"
)

// Logger provides functionality for logging and subscribing to logs.
type Logger struct {
	sync.Mutex
	done       chan struct{} // Channel to signal closure of the logger.
	closeOnce  sync.Once
	q          queue.Queue   // Embeds a queue for managing log messages.
	subscribed []*subscriber // Current subscribers, in subscription order.
	count      atomic.Int32  // len(subscribed), readable without the lock.
}

// subscriber delivers messages to one consumer. Messages wait in q and a
// single pump goroutine moves them to ch in order. The pump is the only
// sender on ch and closes it when it exits, so ch is never closed while a
// send is pending, and a consumer that stops reading costs one blocked
// goroutine until it is unsubscribed, not one per message.
type subscriber struct {
	ch   chan *string
	q    queue.Queue
	done chan struct{}
	once sync.Once
}

// NewLogger initializes and returns a new instance of Logger.
func NewLogger() *Logger {
	l := &Logger{
		done:       make(chan struct{}),
		q:          queue.NewQueue(),
		subscribed: make([]*subscriber, 0),
	}
	go l.broadcastMessages()
	return l
}

// Publish sends a log message to the logger. Messages published while there
// are no subscribers are discarded.
func (l *Logger) Publish(msg string) {
	if l.count.Load() > 0 {
		l.q.Append(msg)
	}
}

// Write allows the Logger to be used as a Writer and in structured logging.
func (l *Logger) Write(p []byte) (n int, err error) {
	l.Publish(string(p))
	return len(p), nil
}

// Subscribe provides a read-only channel to receive log messages.
// This allows external components to "listen" for new logs. The channel is
// closed when the subscription ends: on Unsubscribe or Close. A subscriber
// that is finished with the channel must call Unsubscribe.
func (l *Logger) Subscribe() <-chan *string {
	s := &subscriber{
		ch:   make(chan *string, 100),
		q:    queue.NewQueue(),
		done: make(chan struct{}),
	}

	l.Lock()
	defer l.Unlock()

	select {
	case <-l.done:
		// The logger is closed: hand back an already-closed channel.
		close(s.ch)
		return s.ch
	default:
	}

	l.subscribed = append(l.subscribed, s)
	l.count.Store(int32(len(l.subscribed)))
	go s.pump()
	return s.ch
}

// Unsubscribe ends the subscription that returned ch. Messages still queued
// for it are discarded and ch is closed. It is safe to call more than once,
// and after Close.
func (l *Logger) Unsubscribe(ch <-chan *string) {
	l.Lock()
	defer l.Unlock()

	for i, s := range l.subscribed {
		if s.ch == ch {
			l.subscribed = append(l.subscribed[:i], l.subscribed[i+1:]...)
			l.count.Store(int32(len(l.subscribed)))
			s.end()
			return
		}
	}
}

// Subscribers returns the number of current subscribers.
func (l *Logger) Subscribers() int {
	return int(l.count.Load())
}

// Close stops the logger and ends every subscription, closing their channels.
func (l *Logger) Close() {
	l.closeOnce.Do(func() {
		close(l.done)
		// drain the queue
		l.q.Process(func(any) {})

		l.Lock()
		defer l.Unlock()

		for _, s := range l.subscribed {
			s.end()
		}
		l.subscribed = nil
		l.count.Store(0)
	})
}

func (l *Logger) broadcastMessages() {
	for {
		select {
		case <-l.done:
			return
		case <-l.q.Signal():
		}

		l.q.Process(l.msgToSubscribers)
	}
}

func (l *Logger) msgToSubscribers(e any) {
	msg, ok := e.(string)
	if !ok {
		return
	}

	l.Lock()
	defer l.Unlock()

	for _, s := range l.subscribed {
		s.q.Append(msg)
	}
}

func (s *subscriber) end() {
	s.once.Do(func() { close(s.done) })
}

func (s *subscriber) pump() {
	defer close(s.ch)

	for {
		select {
		case <-s.done:
			return
		case <-s.q.Signal():
		}

		for {
			e, ok := s.q.Next()
			if !ok {
				break
			}
			msg, valid := e.(string)
			if !valid {
				continue
			}

			select {
			case <-s.done:
				return
			case s.ch <- &msg:
			}
		}
	}
}
