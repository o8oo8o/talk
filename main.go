package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/pion/turn/v2"
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
	ReadBufferSize:  1024 * 1024, // 1MB
	WriteBufferSize: 1024 * 1024, // 1MB
}

// Room represents a video chat room
type Room struct {
	clients   map[*websocket.Conn]string
	userCount int
	mutex     sync.RWMutex
}

// Message represents the WebSocket message structure
type Message struct {
	Type   string          `json:"type"`
	RoomID string          `json:"roomId"`
	Data   json.RawMessage `json:"data"`
	UserID string          `json:"userId,omitempty"`
}

var (
	rooms      = make(map[string]*Room)
	roomsMutex sync.RWMutex
)

func newRoom() *Room {
	return &Room{
		clients:   make(map[*websocket.Conn]string),
		userCount: 0,
	}
}

// Generate self-signed certificate
func generateCertificate() (tls.Certificate, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test Company"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour * 24 * 180), // Valid for 180 days
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:              []string{"localhost"},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})

	// Write certificate files
	if err := os.WriteFile("server.crt", certPEM, 0644); err != nil {
		return tls.Certificate{}, err
	}
	if err := os.WriteFile("server.key", privPEM, 0600); err != nil {
		return tls.Certificate{}, err
	}

	return tls.X509KeyPair(certPEM, privPEM)
}

// TURN 服务器配置
const (
	turnPort = 3478
	realm    = "webrtc-turn"
	// 为了简单演示，使用固定的用户名和密码，实际应用中应该动态生成
	username = "webrtc-user"
	password = "webrtc-password"
)

var (
	turnServer *turn.Server
	publicIP   string
)

// 初始化 TURN 服务器
func initTURNServer() error {
	// 获取本机公网 IP
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return err
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)
	publicIP = localAddr.IP.String()

	// 创建 UDP 监听器
	udpListener, err := net.ListenPacket("udp4", fmt.Sprintf("0.0.0.0:%d", turnPort))
	if err != nil {
		return err
	}

	// 创建 TURN 服务器
	turnServer, err = turn.NewServer(turn.ServerConfig{
		Realm: realm,
		// 设置认证回调
		AuthHandler: func(username string, realm string, srcAddr net.Addr) ([]byte, bool) {
			if username == username {
				return turn.GenerateAuthKey(username, realm, password), true
			}
			return nil, false
		},
		PacketConnConfigs: []turn.PacketConnConfig{
			{
				PacketConn: udpListener,
				RelayAddressGenerator: &turn.RelayAddressGeneratorStatic{
					RelayAddress: net.ParseIP(publicIP),
					Address:      "0.0.0.0",
				},
			},
		},
	})

	if err != nil {
		return err
	}

	log.Printf("TURN server is running on %s:%d", publicIP, turnPort)
	return nil
}

// ICEServer 表示 ICE 服务器配置
type ICEServer struct {
	URLs       []string `json:"urls"`
	Username   string   `json:"username,omitempty"`
	Credential string   `json:"credential,omitempty"`
}

func handleWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("Websocket upgrade failed: %v", err)
		return
	}
	defer conn.Close()

	// 等待加入房间消息
	_, message, err := conn.ReadMessage()
	if err != nil {
		log.Printf("Read error: %v", err)
		return
	}

	var msg Message
	if err := json.Unmarshal(message, &msg); err != nil {
		log.Printf("Error parsing message: %v", err)
		return
	}

	if msg.Type != "join" {
		log.Printf("First message must be join")
		return
	}

	roomID := msg.RoomID
	if roomID == "" {
		log.Printf("Room ID is required")
		return
	}

	// 确保房间存在
	roomsMutex.Lock()
	if _, exists := rooms[roomID]; !exists {
		rooms[roomID] = newRoom()
	}
	currentRoom := rooms[roomID]
	roomsMutex.Unlock()

	// 生成用户ID加入房间
	userID := fmt.Sprintf("user_%d", time.Now().UnixNano())

	currentRoom.mutex.Lock()
	currentRoom.clients[conn] = userID
	currentRoom.userCount++
	clientCount := currentRoom.userCount
	currentRoom.mutex.Unlock()

	// 发送房间状态
	type RoomStatus struct {
		Count  int    `json:"count"`
		UserID string `json:"userId"`
	}

	status := RoomStatus{
		Count:  clientCount,
		UserID: userID,
	}

	statusData, err := json.Marshal(status)
	if err != nil {
		log.Printf("Error marshaling room status: %v", err)
		return
	}

	statusMsg := Message{
		Type:   "room_status",
		RoomID: roomID,
		Data:   statusData,
	}

	if err := conn.WriteJSON(statusMsg); err != nil {
		log.Printf("Error sending room status: %v", err)
		return
	}

	log.Printf("Sending room status to user %s: count=%d", userID, clientCount)

	// 创建 ICE 服务器配置
	iceServers := []ICEServer{
		{
			URLs: []string{
				fmt.Sprintf("stun:%s:%d", publicIP, turnPort),
				fmt.Sprintf("turn:%s:%d", publicIP, turnPort),
			},
			Username:   username,
			Credential: password,
		},
	}

	// 发送 ICE 服务器配置
	iceConfig := Message{
		Type: "ice_config",
		Data: json.RawMessage(mustJSON(iceServers)),
	}
	if err := conn.WriteJSON(iceConfig); err != nil {
		log.Printf("Error sending ICE config: %v", err)
		return
	}

	// 清理函数
	defer func() {
		currentRoom.mutex.Lock()
		delete(currentRoom.clients, conn)
		currentRoom.userCount--
		if currentRoom.userCount == 0 {
			roomsMutex.Lock()
			delete(rooms, roomID)
			roomsMutex.Unlock()
		}
		currentRoom.mutex.Unlock()
	}()

	// 消息处理循环
	for {
		_, message, err := conn.ReadMessage()
		if err != nil {
			log.Printf("WebSocket read error for user %s: %v", userID, err)
			break
		}

		var msg Message
		if err := json.Unmarshal(message, &msg); err != nil {
			log.Printf("Message parsing error for user %s: %v", userID, err)
			continue
		}

		log.Printf("Received message from user %s: type=%s", userID, msg.Type)

		// 添加发送者ID
		msg.UserID = userID

		// 重新编码消息
		updatedMessage, err := json.Marshal(msg)
		if err != nil {
			log.Printf("Error encoding message: %v", err)
			continue
		}

		// 广播消息给房间内其他用户
		currentRoom.mutex.RLock()
		for client := range currentRoom.clients {
			if client != conn { // 不送给��己
				err := client.WriteMessage(websocket.TextMessage, updatedMessage)
				if err != nil {
					log.Printf("Write error: %v", err)
				}
			}
		}
		currentRoom.mutex.RUnlock()
	}
}

// 辅助函数：将对象转换为 JSON
func mustJSON(v interface{}) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

func main() {
	// 初始化 TURN 服务器
	if err := initTURNServer(); err != nil {
		log.Fatal("Failed to initialize TURN server:", err)
	}
	defer turnServer.Close()

	// Generate certificate
	cert, err := generateCertificate()
	if err != nil {
		log.Fatal("Failed to generate certificate:", err)
	}

	// Configure TLS
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
	}

	// Setup routes
	http.HandleFunc("/ws", handleWebSocket)
	fs := http.FileServer(http.Dir("."))
	http.Handle("/", fs)

	// Create server
	server := &http.Server{
		Addr:      "0.0.0.0:8080",
		TLSConfig: tlsConfig,
	}

	log.Printf("Server starting on https://localhost:8080")
	if err := server.ListenAndServeTLS("", ""); err != nil {
		log.Fatal("ListenAndServeTLS:", err)
	}
}
