package config

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
)

// checkKeys is a pre-pass over the raw JSON that closes two gaps in
// encoding/json, which otherwise
//   - matches object keys to struct fields case-insensitively (with Unicode
//     folding: "Socket" or "ſocket" both set socket), and
//   - accepts duplicate keys, the last one winning.
//
// Both make a config mean something other than it appears to. checkKeys
// rejects any key that differs from a schema field only by case, and any
// duplicate key at any depth (also inside values the schema doesn't know;
// unknown keys themselves are left to DisallowUnknownFields).
func checkKeys(data []byte, schema reflect.Type) error {
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.UseNumber()
	return walkValue(dec, schema, "")
}

func walkValue(dec *json.Decoder, t reflect.Type, path string) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	delim, ok := tok.(json.Delim)
	if !ok {
		return nil // a scalar
	}
	t = deref(t)
	switch delim {
	case '{':
		var fields map[string]reflect.Type
		if t != nil && t.Kind() == reflect.Struct {
			fields = jsonFields(t)
		}
		seen := make(map[string]bool)
		for dec.More() {
			kt, err := dec.Token()
			if err != nil {
				return err
			}
			key := kt.(string) // object keys are always strings
			keyPath := joinPath(path, key)
			if seen[key] {
				return fmt.Errorf("%s: duplicate key %q", orRoot(path), key)
			}
			seen[key] = true
			var next reflect.Type
			if fields != nil {
				if ft, ok := fields[key]; ok {
					next = ft
				} else {
					for name := range fields {
						if strings.EqualFold(name, key) {
							return fmt.Errorf("%s: key differs from %q only by case (keys are case-sensitive)", keyPath, name)
						}
					}
				}
			}
			if err := walkValue(dec, next, keyPath); err != nil {
				return err
			}
		}
	case '[':
		var elem reflect.Type
		if t != nil && (t.Kind() == reflect.Slice || t.Kind() == reflect.Array) {
			elem = t.Elem()
		}
		for i := 0; dec.More(); i++ {
			if err := walkValue(dec, elem, fmt.Sprintf("%s[%d]", path, i)); err != nil {
				return err
			}
		}
	}
	_, err = dec.Token() // the closing delimiter
	return err
}

// jsonFields maps each exported field's JSON name to its type.
func jsonFields(t reflect.Type) map[string]reflect.Type {
	out := make(map[string]reflect.Type)
	for i := range t.NumField() {
		f := t.Field(i)
		if !f.IsExported() {
			continue
		}
		name, _, _ := strings.Cut(f.Tag.Get("json"), ",")
		if name == "-" {
			continue
		}
		if name == "" {
			name = f.Name
		}
		out[name] = f.Type
	}
	return out
}

func deref(t reflect.Type) reflect.Type {
	for t != nil && t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	return t
}

func joinPath(parent, key string) string {
	if parent == "" {
		return key
	}
	return parent + "." + key
}

func orRoot(path string) string {
	if path == "" {
		return "top level"
	}
	return path
}
