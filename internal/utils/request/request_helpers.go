// Package request hold whole logic associated with request helpers functions
package request

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	// "github.com/slodkiadrianek/octopus/internal/DTO"
)

func SendHTTP(ctx context.Context, URL, authorizationHeader, method string, body []byte, readBody bool) (int,
	map[string]any, error,
) {
	httpClient := &http.Client{}
	req, err := http.NewRequestWithContext(ctx, method, URL, bytes.NewBuffer(body))
	if err != nil {
		return 0, map[string]any{}, err
	}
	if authorizationHeader != "" {
		req.Header.Add("Authorization", authorizationHeader)
	}

	req.Header.Set("Content-Type", "application/json; charset=UTF-8")
	response, err := httpClient.Do(req)
	if err != nil {
		return 0, map[string]any{}, err
	}
	defer func() {
		if closeErr := response.Body.Close(); closeErr != nil {
			fmt.Printf("failed to close response body: %s", closeErr.Error())
		}
	}()

	var bodyFromResponse map[string]any
	if readBody {
		err = json.NewDecoder(response.Body).Decode(&bodyFromResponse)
		fmt.Println(err)
		if err != nil {
			return 0, map[string]any{}, err
		}
	}
	return response.StatusCode, bodyFromResponse, nil
}

func ReadUserIDFromToken(r *http.Request) (int, error) {
	userID, ok := r.Context().Value("id").(int)
	if !ok || userID == 0 {
		err := errors.New("failed to read user from context")
		return 0, err
	}
	return userID, nil
}

func ReadBody[T any](r *http.Request) (*T, error) {
	if r.Body == nil {
		return nil, errors.New("no request body provided")
	}
	var body T

	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	err := decoder.Decode(&body)
	if err != nil {
		return nil, err
	}

	return &body, nil
}

func ReadQueryParam(r *http.Request, QueryName string) string {
	name := r.URL.Query().Get(QueryName)
	return name
}

func MatchRoute(routeURL, URLPath string) bool {
	splittedRouteURL := strings.Split(strings.Trim(routeURL, "/"), "/")
	splittedURLPath := strings.Split(strings.Trim(URLPath, "/"), "/")

	if len(splittedRouteURL) != len(splittedURLPath) {
		return false
	}

	for i := range len(splittedRouteURL) {
		if strings.Contains(splittedRouteURL[i], ":") {
			continue
		}
		if splittedURLPath[i] != splittedRouteURL[i] {
			return false
		}
	}
	return true
}

func ReadParam(r *http.Request, paramToRead string) (string, error) {
	path := r.URL.Path
	routeKeyPath := r.Context().Value("routeKeyPath")
	s, ok := routeKeyPath.(string)
	if !ok {
		return "", errors.New("failed to read context routeKeyPath, must be type string")
	}
	splittedPath := strings.Split(strings.Trim(path, "/"), "/")
	splittedRouteKeyPath := strings.Split(strings.Trim(s, "/"), "/")

	param := ""
	for i := range len(splittedPath) {
		if strings.Contains(splittedRouteKeyPath[i], ":") && splittedRouteKeyPath[i][1:] == paramToRead {
			param = splittedPath[i]
			break
		}
	}
	if param == "" {
		return "", errors.New("the is no parameter called: " + paramToRead)
	}
	return param, nil
}

func ReadAllParams(r *http.Request) (map[string]string, error) {
	path := r.URL.Path
	routeKeyPath := r.Context().Value("routeKeyPath")
	s, ok := routeKeyPath.(string)
	if !ok {
		return nil, errors.New("failed to read context routeKeyPath, must be type string")
	}

	splittedPath := strings.Split(strings.Trim(path, "/"), "/")
	splittedRouteKeyPath := strings.Split(strings.Trim(s, "/"), "/")

	params := make(map[string]string)
	for i := range len(splittedPath) {
		if strings.Contains(splittedRouteKeyPath[i], ":") {
			paramName := splittedRouteKeyPath[i][1:]
			params[paramName] = splittedPath[i]
		}
	}
	return params, nil
}

func RemoveLastCharacterFromURL(route string) string {
	if string(route[len(route)-1]) == "/" {
		route = route[:len(route)-1]
	}
	return route
}
