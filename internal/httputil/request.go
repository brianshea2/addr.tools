package httputil

import (
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
)

var (
	ErrAmbiguousValues     = errors.New("differing values found")
	ErrValueUnexpectedType = errors.New("value is an unexpected type")
)

type JSONObject map[string]interface{}

type RequestValues struct {
	req     *http.Request
	body    []byte
	readErr error
	form    url.Values
	jsonObj JSONObject
	query   url.Values
}

// returns a *RequestValues which lazily parses body and url values
func ParseRequest(req *http.Request) *RequestValues {
	return &RequestValues{req: req}
}

func (p *RequestValues) Body() ([]byte, error) {
	if p.body == nil && p.readErr == nil {
		p.body, p.readErr = io.ReadAll(p.req.Body)
	}
	return p.body, p.readErr
}

func (p *RequestValues) BodyText() (string, error) {
	body, err := p.Body()
	return string(body), err
}

func (p *RequestValues) ContentType() string {
	t := p.req.Header.Get("Content-Type")
	if len(t) > 0 {
		t, _, _ = mime.ParseMediaType(t)
	}
	return t
}

func (p *RequestValues) Form() (url.Values, error) {
	if p.form == nil {
		body, err := p.BodyText()
		if err != nil {
			return nil, err
		}
		p.form, _ = url.ParseQuery(body)
		if p.form == nil {
			p.form = make(url.Values)
		}
	}
	return p.form, nil
}

func (p *RequestValues) JSONObject() (JSONObject, error) {
	if p.jsonObj == nil {
		body, err := p.Body()
		if err != nil {
			return nil, err
		}
		json.Unmarshal(body, &p.jsonObj)
		if p.jsonObj == nil {
			p.jsonObj = make(JSONObject)
		}
	}
	return p.jsonObj, nil
}

func (p *RequestValues) Query() url.Values {
	if p.query == nil {
		p.query, _ = url.ParseQuery(p.req.URL.RawQuery)
		if p.query == nil {
			p.query = make(url.Values)
		}
	}
	return p.query
}

// returns all request values associated with key.
// parses values from request body and url based on method and content-type.
func (p *RequestValues) Values(key string) (vals []interface{}, err error) {
	switch p.req.Method {
	case http.MethodPost, http.MethodPut, http.MethodDelete:
		switch p.ContentType() {
		// if no content-type is specified, assume url-encoded form values
		case "application/x-www-form-urlencoded", "":
			var form url.Values
			form, err = p.Form()
			if err != nil {
				return
			}
			for _, v := range form[key] {
				vals = append(vals, v)
			}
		case "application/json":
			var obj JSONObject
			obj, err = p.JSONObject()
			if err != nil {
				return
			}
			if v, ok := obj[key]; ok {
				vals = append(vals, v)
			}
		}
		fallthrough
	case http.MethodGet:
		for _, v := range p.Query()[key] {
			vals = append(vals, v)
		}
	}
	return
}

// returns the request value associated with key.
// if key is not found, returns empty string and nil error.
// if differing values are found, returns the first value and ErrAmbiguousValues.
// if an associated value is not a string, returns the first string, if any, and ErrValueUnexpectedType.
// may also return errors related to parsing the request.
func (p *RequestValues) GetString(key string) (string, error) {
	vals, err := p.Values(key)
	if err != nil || len(vals) == 0 {
		return "", err
	}
	var str string
	var strFound bool
	for _, v := range vals {
		if s, ok := v.(string); ok {
			if !strFound {
				str = s
				strFound = true
			} else if s != str {
				err = ErrAmbiguousValues
			}
		} else {
			err = ErrValueUnexpectedType
		}
		if err != nil && strFound {
			break
		}
	}
	return str, err
}
