package main

import (
	"context"
	"encoding/pem"
	"errors"
	"flag"
	"io"
	"net"
	"os"

	proto_message "github.com/11090815/grpc-example/proto-message"
	"github.com/11090815/hyperchain/bccsp"
	"google.golang.org/grpc"
)

type Server struct {
	key      []byte
	server   *grpc.Server
	listener net.Listener
}

func NewServer(address string, key []byte) (*Server, error) {
	var err error
	s := new(Server)
	if s.listener, err = net.Listen("tcp", address); err != nil {
		return nil, err
	}

	s.server = grpc.NewServer()

	if len(key) == 0 {
		key, _ = bccsp.GetRandomBytes(32)
	}

	s.key = key

	proto_message.RegisterEncrypterServer(s.server, s)

	return s, nil
}

func (s *Server) Start() {
	s.server.Serve(s.listener)
}

func (s *Server) Stop() {
	s.server.Stop()
}

func (s *Server) Encrypt(ctx context.Context, req *proto_message.Request) (*proto_message.Response, error) {
	var err error
	var response proto_message.Response

	if len(req.Plaintext) == 0 {
		return nil, errors.New("encrypt: plaintext should not be empty")
	}

	response.Ciphertext, err = bccsp.AESCBCPKCS7Encrypt(s.key, req.Plaintext)
	if err != nil {
		return nil, err
	}

	return &response, nil
}

func (s *Server) EncryptStream(stream proto_message.Encrypter_EncryptStreamServer) error {
	for {
		req, err := stream.Recv()
		if err != nil && err == io.EOF {
			return nil
		} else if err != nil {
			return err
		} else {
			if len(req.Plaintext) == 0 {
				return errors.New("encrypt: plaintext should not be empty")
			}
			var err error
			var response proto_message.Response
			if response.Ciphertext, err = bccsp.AESCBCPKCS7Encrypt(s.key, req.Plaintext); err != nil {
				return err
			}
			if err = stream.Send(&response); err != nil {
				return err
			}
		}
	}
}

var address string

func init() {
	flag.StringVar(&address, "a", "127.0.0.1:9753", "服务端监听的地址，格式必须是 ip:port")
}

func main() {
	flag.Parse()

	keyPEM, err := os.ReadFile("aes_key.pem")
	if err != nil {
		panic(err)
	}

	block, _ := pem.Decode(keyPEM)

	server, err := NewServer(address, block.Bytes)
	if err != nil {
		panic(err)
	}

	server.Start()
}
