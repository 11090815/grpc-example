package main

import (
	"context"
	"flag"
	"io"

	proto_message "github.com/11090815/grpc-example/proto-message"
	"github.com/11090815/hyperchain/common/hlogging"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type Client struct {
	client proto_message.EncrypterClient
	logger *hlogging.HyperchainLogger
}

func NewClient(address string) (*Client, error) {
	var err error
	c := new(Client)
	var conn *grpc.ClientConn

	if conn, err = grpc.Dial(address, grpc.WithTransportCredentials(insecure.NewCredentials())); err != nil {
		return nil, err
	}

	c.client = proto_message.NewEncrypterClient(conn)

	c.logger = hlogging.MustGetLogger("client")
	hlogging.Init(hlogging.Config{
		Format: hlogging.ShortFuncFormat,
	})
	hlogging.ActivateSpec("client=info")

	return c, nil
}

func (c *Client) Encrypt(message []byte) ([]byte, error) {
	req := &proto_message.Request{Plaintext: message}

	res, err := c.client.Encrypt(context.Background(), req)
	if err != nil {
		return nil, err
	}

	return res.Ciphertext, nil
}

func (c *Client) EncryptStream(msgs [][]byte) ([][]byte, error) {
	stream, err := c.client.EncryptStream(context.Background())
	if err != nil {
		return nil, err
	}

	ciphertexts := make([][]byte, 0)
	finished := make(chan struct{})
	errCh := make(chan error)
	go func() {
		for {
			resp, err := stream.Recv()
			if err != nil && err == io.EOF {
				close(finished)
				c.logger.Debug("Encrypt finished.")
				return
			} else if err != nil {
				close(finished)
				errCh <- err
				c.logger.Errorf("Received error: [%s].", err.Error())
				return
			} else {
				c.logger.Infof("Encrypted result: [%x].", resp.Ciphertext)
				ciphertexts = append(ciphertexts, resp.Ciphertext)

			}
		}
	}()

	for _, msg := range msgs {
		if err = stream.Send(&proto_message.Request{Plaintext: msg}); err != nil {
			return nil, err
		}
	}
	stream.CloseSend()

	<-finished

	select {
	case err = <-errCh:
		return nil, err
	default:
		return ciphertexts, err
	}
}

var address string

func init() {
	flag.StringVar(&address, "a", "127.0.0.1:9753", "服务端监听的地址，格式必须是 ip:port")
}

func main() {
	flag.Parse()

	client, err := NewClient(address)
	if err != nil {
		panic(err)
	}

	msgs := [][]byte{
		[]byte("Author submission process overview and support article."),
		[]byte("Checking the status of your submission."),
		[]byte("Co-author verification FAQs."),
		[]byte("Preparing to submit your revision"),
		[]byte("Submitting your revision and support article"),
	}

	client.EncryptStream(msgs)
}
