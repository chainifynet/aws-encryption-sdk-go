// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package format

// MessageType is the type of the message. The type indicates the kind of
// structure. The only supported type is [CustomerAEData].
type MessageType int

// CustomerAEData is a customer authenticated encrypted data. Its type value is
// 128, encoded as byte 80 in hexadecimal notation.
const CustomerAEData MessageType = 128
