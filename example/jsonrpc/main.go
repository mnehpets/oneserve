package main

import (
	"context"
	"log"
	"net/http"

	"github.com/mnehpets/oneserve/endpoint"
	"github.com/mnehpets/oneserve/jsonrpc"
)

type MathMethods struct{}

func (m *MathMethods) Add(ctx context.Context, a, b int) (int, error) {
	return a + b, nil
}

func (m *MathMethods) Sub(ctx context.Context, args struct {
	A int `json:"a"`
	B int `json:"b"`
}) (int, error) {
	return args.A - args.B, nil
}

func main() {
	e := jsonrpc.NewEndpoint()
	e.Register("math", &MathMethods{})

	http.Handle("/rpc", endpoint.Handler(e.Endpoint))

	log.Println("Starting server on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
