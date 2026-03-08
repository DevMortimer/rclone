package api

import (
	"bytes"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"io"
	"reflect"
	"sort"
	"strconv"
	"strings"
)

func marshalPlist(v any) ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteString(`<?xml version="1.0" encoding="UTF-8"?>`)
	buf.WriteString(`<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">`)
	buf.WriteString(`<plist version="1.0">`)
	if err := writePlistValue(&buf, v); err != nil {
		return nil, err
	}
	buf.WriteString(`</plist>`)
	return buf.Bytes(), nil
}

func writePlistValue(w io.Writer, v any) error {
	switch val := v.(type) {
	case map[string]any:
		return writePlistMap(w, val)
	case map[string]string:
		m := make(map[string]any, len(val))
		for k, v := range val {
			m[k] = v
		}
		return writePlistMap(w, m)
	case []byte:
		_, err := fmt.Fprintf(w, "<data>%s</data>", base64.StdEncoding.EncodeToString(val))
		return err
	case string:
		return writeXMLTextElement(w, "string", val)
	case bool:
		tag := "false"
		if val {
			tag = "true"
		}
		_, err := fmt.Fprintf(w, "<%s/>", tag)
		return err
	case int:
		return writeXMLTextElement(w, "integer", strconv.Itoa(val))
	case int64:
		return writeXMLTextElement(w, "integer", strconv.FormatInt(val, 10))
	case uint64:
		return writeXMLTextElement(w, "integer", strconv.FormatUint(val, 10))
	case []any:
		if _, err := io.WriteString(w, "<array>"); err != nil {
			return err
		}
		for _, item := range val {
			if err := writePlistValue(w, item); err != nil {
				return err
			}
		}
		_, err := io.WriteString(w, "</array>")
		return err
	default:
		rv := reflect.ValueOf(v)
		switch rv.Kind() {
		case reflect.Slice, reflect.Array:
			if _, err := io.WriteString(w, "<array>"); err != nil {
				return err
			}
			for i := 0; i < rv.Len(); i++ {
				if err := writePlistValue(w, rv.Index(i).Interface()); err != nil {
					return err
				}
			}
			_, err := io.WriteString(w, "</array>")
			return err
		case reflect.Map:
			m := make(map[string]any, rv.Len())
			iter := rv.MapRange()
			for iter.Next() {
				m[fmt.Sprint(iter.Key().Interface())] = iter.Value().Interface()
			}
			return writePlistMap(w, m)
		default:
			return fmt.Errorf("unsupported plist type %T", v)
		}
	}
}

func writePlistMap(w io.Writer, v map[string]any) error {
	if _, err := io.WriteString(w, "<dict>"); err != nil {
		return err
	}
	keys := make([]string, 0, len(v))
	for k := range v {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if err := writeXMLTextElement(w, "key", k); err != nil {
			return err
		}
		if err := writePlistValue(w, v[k]); err != nil {
			return err
		}
	}
	_, err := io.WriteString(w, "</dict>")
	return err
}

func writeXMLTextElement(w io.Writer, tag, value string) error {
	if _, err := fmt.Fprintf(w, "<%s>", tag); err != nil {
		return err
	}
	if err := xml.EscapeText(w, []byte(value)); err != nil {
		return err
	}
	_, err := fmt.Fprintf(w, "</%s>", tag)
	return err
}

func unmarshalPlist(data []byte) (any, error) {
	decoder := xml.NewDecoder(bytes.NewReader(data))
	for {
		tok, err := decoder.Token()
		if err != nil {
			return nil, err
		}
		start, ok := tok.(xml.StartElement)
		if !ok {
			continue
		}
		if start.Name.Local != "plist" {
			return nil, fmt.Errorf("unexpected plist root %q", start.Name.Local)
		}
		for {
			tok, err = decoder.Token()
			if err != nil {
				return nil, err
			}
			switch elem := tok.(type) {
			case xml.StartElement:
				return readPlistValue(decoder, elem)
			case xml.EndElement:
				if elem.Name.Local == "plist" {
					return nil, fmt.Errorf("empty plist document")
				}
			}
		}
	}
}

func readPlistValue(decoder *xml.Decoder, start xml.StartElement) (any, error) {
	switch start.Name.Local {
	case "dict":
		out := map[string]any{}
		for {
			tok, err := decoder.Token()
			if err != nil {
				return nil, err
			}
			switch elem := tok.(type) {
			case xml.EndElement:
				if elem.Name.Local == "dict" {
					return out, nil
				}
			case xml.StartElement:
				if elem.Name.Local != "key" {
					return nil, fmt.Errorf("expected plist key, got %q", elem.Name.Local)
				}
				key, err := readPlistText(decoder, "key")
				if err != nil {
					return nil, err
				}
				for {
					tok, err = decoder.Token()
					if err != nil {
						return nil, err
					}
					if valueElem, ok := tok.(xml.StartElement); ok {
						value, err := readPlistValue(decoder, valueElem)
						if err != nil {
							return nil, err
						}
						out[key] = value
						break
					}
				}
			}
		}
	case "array":
		var out []any
		for {
			tok, err := decoder.Token()
			if err != nil {
				return nil, err
			}
			switch elem := tok.(type) {
			case xml.EndElement:
				if elem.Name.Local == "array" {
					return out, nil
				}
			case xml.StartElement:
				value, err := readPlistValue(decoder, elem)
				if err != nil {
					return nil, err
				}
				out = append(out, value)
			}
		}
	case "string":
		return readPlistText(decoder, "string")
	case "integer":
		text, err := readPlistText(decoder, "integer")
		if err != nil {
			return nil, err
		}
		return strconv.ParseInt(strings.TrimSpace(text), 10, 64)
	case "data":
		text, err := readPlistText(decoder, "data")
		if err != nil {
			return nil, err
		}
		return base64.StdEncoding.DecodeString(strings.TrimSpace(text))
	case "true":
		return true, consumeEndElement(decoder, "true")
	case "false":
		return false, consumeEndElement(decoder, "false")
	default:
		return nil, fmt.Errorf("unsupported plist element %q", start.Name.Local)
	}
}

func readPlistText(decoder *xml.Decoder, endName string) (string, error) {
	var builder strings.Builder
	for {
		tok, err := decoder.Token()
		if err != nil {
			return "", err
		}
		switch elem := tok.(type) {
		case xml.CharData:
			builder.Write([]byte(elem))
		case xml.EndElement:
			if elem.Name.Local == endName {
				return builder.String(), nil
			}
		}
	}
}

func consumeEndElement(decoder *xml.Decoder, endName string) error {
	for {
		tok, err := decoder.Token()
		if err != nil {
			return err
		}
		if elem, ok := tok.(xml.EndElement); ok && elem.Name.Local == endName {
			return nil
		}
	}
}

func plistMap(v any) (map[string]any, error) {
	m, ok := v.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("expected plist dict, got %T", v)
	}
	return m, nil
}

func plistString(v any) (string, error) {
	s, ok := v.(string)
	if !ok {
		return "", fmt.Errorf("expected plist string, got %T", v)
	}
	return s, nil
}

func plistBytes(v any) ([]byte, error) {
	b, ok := v.([]byte)
	if !ok {
		return nil, fmt.Errorf("expected plist data, got %T", v)
	}
	return b, nil
}

func plistInt(v any) (int64, error) {
	switch n := v.(type) {
	case int64:
		return n, nil
	case int:
		return int64(n), nil
	default:
		return 0, fmt.Errorf("expected plist integer, got %T", v)
	}
}

func nestedPlistString(m map[string]any, keys ...string) (string, error) {
	cur := any(m)
	for _, key := range keys {
		next, err := plistMap(cur)
		if err != nil {
			return "", err
		}
		var ok bool
		cur, ok = next[key]
		if !ok {
			return "", fmt.Errorf("missing plist key %q", key)
		}
	}
	return plistString(cur)
}
