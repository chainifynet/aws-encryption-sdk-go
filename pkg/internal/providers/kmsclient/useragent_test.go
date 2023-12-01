// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package kmsclient

import (
	"context"
	"net/http"
	"testing"

	"github.com/aws/smithy-go/middleware"
	smithyhttp "github.com/aws/smithy-go/transport/http"
	"github.com/stretchr/testify/assert"
)

func Test_userAgentAppender_ID(t *testing.T) {
	mw := &userAgentAppender{}
	assert.Equal(t, "userAgentAppender", mw.ID())
}

func Test_userAgentAppender_HandleBuild(t *testing.T) {
	tests := []struct {
		name            string
		request         interface{}
		userAgentAppend string
		want            string
		wantErr         bool
		wantErrStr      string
	}{
		{
			name: "Append to existing user-agent",
			request: func() interface{} {
				req := smithyhttp.NewStackRequest().(*smithyhttp.Request)
				req.Request, _ = http.NewRequest(http.MethodGet, "https://example.com", nil)
				req.Header.Set("user-agent", "InitialUserAgent")
				return req
			}(),
			userAgentAppend: "MyAppender",
			want:            "InitialUserAgent MyAppender",
			wantErr:         false,
		},
		{
			name: "Append to non initialized user-agent",
			request: func() interface{} {
				req := smithyhttp.NewStackRequest().(*smithyhttp.Request)
				req.Request, _ = http.NewRequest(http.MethodGet, "https://example.com", nil)
				return req
			}(),
			userAgentAppend: "CustomUserAgent",
			want:            "CustomUserAgent",
			wantErr:         false,
		},
		{
			name: "Non-smithyhttp Request",
			request: func() *http.Request {
				// here, we are intentionally passing a regular http.Request
				// which is not a smithyhttp.Request to trigger assertion error
				req, _ := http.NewRequest(http.MethodGet, "https://example.com", nil)
				return req
			}(),
			userAgentAppend: "MyUserAgent",
			want:            "",
			wantErr:         true,
			wantErrStr:      "unknown transport type",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			appender := &userAgentAppender{value: tt.userAgentAppend}

			// mock BuildHandler
			next := middleware.BuildHandlerFunc(func(ctx context.Context, in middleware.BuildInput) (
				out middleware.BuildOutput, metadata middleware.Metadata, err error,
			) {
				return out, metadata, nil
			})

			// call the HandleBuild method with the request and mock BuildHandler
			_, _, err := appender.HandleBuild(ctx, middleware.BuildInput{Request: tt.request}, next)

			if tt.wantErr {
				assert.Error(t, err)
				if tt.wantErrStr != "" {
					assert.ErrorContains(t, err, tt.wantErrStr)
				}
			} else {
				assert.NoError(t, err)
				if req, ok := tt.request.(*smithyhttp.Request); ok {
					got := req.Header.Get("user-agent")
					assert.Equal(t, tt.want, got)
				}
			}
		})
	}
}

func Test_withUserAgentAppender(t *testing.T) {
	tests := []struct {
		name           string
		userAgentValue string
	}{
		{
			name:           "Append user agent value",
			userAgentValue: "CustomUserAgent",
		},
		{
			name:           "Append empty user agent value",
			userAgentValue: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stack := middleware.NewStack("testStack", nil)

			// apply withUserAgentAppender function
			err := withUserAgentAppender(tt.userAgentValue)(stack)
			assert.NoError(t, err)

			// check if userAgentAppender is added to the stack
			_, found := stack.Build.Get("userAgentAppender")
			assert.True(t, found, "userAgentAppender should be added to the middleware stack")
		})
	}
}
