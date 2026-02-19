// Example JSON-RPC server demonstrating basic usage of the jsonrpc package.
//
// Run with: go run example/jsonrpc/main.go
//
// Test with:
//
//	curl -X POST http://localhost:8080/rpc \
//	  -H "Content-Type: application/json" \
//	  -d '{"jsonrpc":"2.0","method":"math.Add","params":[5,3],"id":1}'
//
//	curl -X POST http://localhost:8080/rpc \
//	  -H "Content-Type: application/json" \
//	  -d '{"jsonrpc":"2.0","method":"Echo","params":["hello"],"id":2}'
//
//	curl -X POST http://localhost:8080/rpc \
//	  -H "Content-Type: application/json" \
//	  -d '[{"jsonrpc":"2.0","method":"math.Add","params":[1,2],"id":1},{"jsonrpc":"2.0","method":"Echo","params":["world"],"id":2}]'
package main

import (
	"context"
	"log"
	"net/http"

	"github.com/mnehpets/oneserve/endpoint"
	"github.com/mnehpets/oneserve/jsonrpc"
)

// MathService provides mathematical operations
type MathService struct{}

// Add adds two integers and returns the result.
// Available as "math.Add" via JSON-RPC.
func (m *MathService) Add(ctx context.Context, a, b int) (int, error) {
	return a + b, nil
}

// Subtract subtracts b from a and returns the result.
// Available as "math.Subtract" via JSON-RPC.
func (m *MathService) Subtract(ctx context.Context, a, b int) (int, error) {
	return a - b, nil
}

// EchoService provides echo functionality
type EchoService struct{}

// Echo returns the message unchanged.
// Available as "Echo" (no namespace) via JSON-RPC.
func (e *EchoService) Echo(ctx context.Context, message string) (string, error) {
	return message, nil
}

// Ping responds with "pong".
// Available as "Ping" (no namespace) via JSON-RPC.
func (e *EchoService) Ping(ctx context.Context) (string, error) {
	return "pong", nil
}

func main() {
	// Create a new JSON-RPC endpoint
	rpcEndpoint := jsonrpc.NewEndpoint()

	// Register services with namespaces
	rpcEndpoint.Register("math", &MathService{})

	// Register services without namespaces (direct method names)
	rpcEndpoint.Register("", &EchoService{})

	// Create HTTP handler using endpoint.Handler for processor chain support
	handler := endpoint.Handler(rpcEndpoint.Endpoint)

	// Setup routes
	mux := http.NewServeMux()
	mux.Handle("/rpc", handler)

	// Add a simple health check
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	log.Println("JSON-RPC server listening on :8080")
	log.Println("Endpoints:")
	log.Println("  POST /rpc    - JSON-RPC endpoint")
	log.Println("  GET  /health - Health check")
	log.Println("")
	log.Println("Example requests:")
	log.Println(`  curl -X POST http://localhost:8080/rpc -H "Content-Type: application/json" -d '{"jsonrpc":"2.0","method":"math.Add","params":[5,3],"id":1}'`)
	log.Println(`  curl -X POST http://localhost:8080/rpc -H "Content-Type: application/json" -d '{"jsonrpc":"2.0","method":"Echo","params":["hello"],"id":2}'`)

	if err := http.ListenAndServe(":8080", mux); err != nil {
		log.Fatal(err)
	}
}
