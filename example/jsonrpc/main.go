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

func (m *MathMethods) Subtract(ctx context.Context, a, b int) (int, error) {
	return a - b, nil
}

func (m *MathMethods) Multiply(ctx context.Context, a, b int) (int, error) {
	return a * b, nil
}

func (m *MathMethods) Divide(ctx context.Context, a, b int) (int, error) {
	if b == 0 {
		return 0, jsonrpc.NewInvalidParamsError("division by zero")
	}
	return a / b, nil
}

func main() {
	e := jsonrpc.NewEndpoint()
	e.Register("math", &MathMethods{})

	http.Handle("/rpc", endpoint.Handler(e.Endpoint))

	log.Println("JSON-RPC server listening on :8080")
	log.Println("Try: curl -X POST http://localhost:8080/rpc -d '{\"jsonrpc\":\"2.0\",\"method\":\"math.Add\",\"params\":[5,3],\"id\":1}'")
	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatal(err)
	}
}
