// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"log"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"
)

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	CheckOrigin:     func(r *http.Request) bool { return true },
}

// WSLogsHandler godoc
//
// @Summary      Stream session logs (WebSocket)
// @Description  Upgrades the HTTP connection to a WebSocket and streams the session's log records as UTF-8 text frames, one JSON object per frame, in order. Only records written while the client is connected are delivered; nothing is buffered for later. The server sends a ping every 30 seconds and drops a client that has not answered within 60 seconds, so a client must keep reading the connection (which answers the pings). Messages the client sends are ignored. When the session ends, the server sends a close frame.
// @Tags         sessions
// @Param        session_token  path  string  true  "Session token (UUID)"
// @Success      101  "Switching Protocols (WebSocket upgrade)"
// @Failure      400  {object}  ErrorResponse  "Invalid session token"
// @Failure      404  {object}  ErrorResponse  "Session not found"
// @Router       /sessions/{session_token}/ws/logs [get]
// @Header  	 101  {string}  Upgrade     "websocket"
// @Header  	 101  {string}  Connection  "Upgrade"
func (v *V1Handlers) WSLogsHandler(w http.ResponseWriter, r *http.Request) {
	sid := mux.Vars(r)["session_token"]

	// Check if the session token is valid
	token, err := uuid.Parse(sid)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid session token", err)
		return
	}
	// Check if the session exists
	// and if the session is not already terminated
	sess := v.mgr.GetSession(token)
	if sess == nil {
		writeError(w, http.StatusNotFound, "session not found", ErrNotFound)
		return
	}

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("ws upgrade failed: %v", err)
		return
	}

	conn.SetReadLimit(1 << 20)
	_ = conn.SetReadDeadline(time.Now().Add(wsPongWait))
	conn.SetPongHandler(func(string) error {
		_ = conn.SetReadDeadline(time.Now().Add(wsPongWait))
		return nil
	})

	ps := sess.PubSub()
	ch := ps.Subscribe()
	end := func() {
		ps.Unsubscribe(ch)
		_ = conn.Close()
	}

	go readLoop(conn, end)
	go writeLoop(conn, ch, end)
	if v.log != nil {
		v.log.Info("connected to session log stream")
	}
}

const (
	wsPingPeriod = 30 * time.Second
	wsPongWait   = 60 * time.Second
	wsWriteWait  = 10 * time.Second
)

// readLoop reads (and discards) whatever the client sends. Reading is what
// processes the client's pongs and close frame, so it is how a client that
// disconnects, or stops answering pings, is noticed: the read fails and the
// subscription ends at once. Without it, a gone client stayed subscribed for
// the rest of the session.
func readLoop(conn *websocket.Conn, end func()) {
	defer end()

	for {
		if _, _, err := conn.ReadMessage(); err != nil {
			return
		}
	}
}

func writeLoop(conn *websocket.Conn, ch <-chan *string, end func()) {
	defer end()

	ping := time.NewTicker(wsPingPeriod)
	defer ping.Stop()

	for {
		select {
		case msg, ok := <-ch:
			_ = conn.SetWriteDeadline(time.Now().Add(wsWriteWait))
			if !ok {
				_ = conn.WriteMessage(websocket.CloseMessage,
					websocket.FormatCloseMessage(websocket.CloseNormalClosure, "session ended"))
				return
			}
			if err := conn.WriteMessage(websocket.TextMessage, []byte(*msg)); err != nil {
				return
			}
		case <-ping.C:
			_ = conn.SetWriteDeadline(time.Now().Add(wsWriteWait))
			if err := conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}
}
