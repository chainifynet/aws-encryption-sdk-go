// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package kmsclient

import (
	"context"
	"fmt"

	"github.com/aws/smithy-go/middleware"
	smithyhttp "github.com/aws/smithy-go/transport/http"
)

type userAgentAppender struct {
	value string
}

func (*userAgentAppender) ID() string {
	return "userAgentAppender"
}

func (m *userAgentAppender) HandleBuild(ctx context.Context, in middleware.BuildInput, next middleware.BuildHandler) (
	out middleware.BuildOutput, metadata middleware.Metadata, err error,
) {
	r, ok := in.Request.(*smithyhttp.Request)
	if !ok {
		return out, metadata, fmt.Errorf("unknown transport type %T", in.Request)
	}

	if ua := r.Header.Get("user-agent"); ua != "" {
		r.Header.Set("user-agent", fmt.Sprintf("%s %s", ua, m.value))
	} else {
		r.Header.Set("user-agent", m.value)
	}

	return next.HandleBuild(ctx, in) //nolint:wrapcheck
}

func withUserAgentAppender(ua string) func(*middleware.Stack) error {
	return func(stack *middleware.Stack) error {
		return stack.Build.Add(&userAgentAppender{value: ua}, middleware.After) //nolint:wrapcheck
	}
}
