// extract reads the W3C WebAuthn L3 section 16 vectors out of the Go source
// that transcribes them and writes them as JSON. Usage: extract <src.go> <out.json>
package main

import (
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strconv"
)

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: extract <src.go> <out.json>")
		os.Exit(2)
	}
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, os.Args[1], nil, parser.ParseComments)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	out := map[string][]map[string]string{}
	for _, d := range f.Decls {
		fn, ok := d.(*ast.FuncDecl)
		if !ok {
			continue
		}
		var key string
		switch fn.Name.Name {
		case "TestSpecVectors_Registration_E2E":
			key = "registration"
		case "TestSpecVectors_Authentication_E2E":
			key = "authentication"
		default:
			continue
		}
		ast.Inspect(fn, func(n ast.Node) bool {
			cl, ok := n.(*ast.CompositeLit)
			if !ok {
				return true
			}
			if _, isSlice := cl.Type.(*ast.ArrayType); isSlice {
				return true
			}
			row := map[string]string{}
			for _, e := range cl.Elts {
				kv, ok := e.(*ast.KeyValueExpr)
				if !ok {
					return true
				}
				k, ok := kv.Key.(*ast.Ident)
				if !ok {
					return true
				}
				if lit, ok := kv.Value.(*ast.BasicLit); ok && lit.Kind == token.STRING {
					s, err := strconv.Unquote(lit.Value)
					if err == nil {
						row[k.Name] = s
					}
				} else if b, ok := kv.Value.(*ast.Ident); ok && (b.Name == "true" || b.Name == "false") {
					row[k.Name] = b.Name
				}
			}
			if row["name"] != "" {
				out[key] = append(out[key], row)
			}
			return false
		})
	}
	b, err := json.MarshalIndent(out, "", " ")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := os.WriteFile(os.Args[2], append(b, '\n'), 0o644); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Printf("registration=%d authentication=%d\n", len(out["registration"]), len(out["authentication"]))
}
