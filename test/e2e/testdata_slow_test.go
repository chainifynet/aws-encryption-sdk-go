// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//go:build integration && slow

package main_test

import (
	_ "embed"
)

var (
	//go:embed testdata/random_512b.bin
	random512b []byte
	//go:embed testdata/random_1023b.bin
	random1023b []byte
	//go:embed testdata/random_1024b.bin
	random1024b []byte
	//go:embed testdata/random_1025b.bin
	random1025b []byte
	//go:embed testdata/random_32kb.bin
	random32kb []byte
	//go:embed testdata/random_512kb.bin
	random512kb []byte
	//go:embed testdata/random_1mb.bin
	random1mb []byte
	//go:embed testdata/small_file.txt
	smallFile []byte
	//go:embed testdata/users.json
	usersJson []byte
	//go:embed testdata/users_pretty.json
	usersJsonPretty []byte

	//go:embed testdata/static_1.key
	staticKey1 []byte
	//go:embed testdata/static_2.key
	staticKey2 []byte

	//go:embed testdata/encrypted_static.enc
	random32kbEncryptedStatic []byte
)

var testFilesAll = []testFile{
	{"random_512b.bin", random512b},
	{"random_1023b.bin", random1023b},
	{"random_1024b.bin", random1024b},
	{"random_1025b.bin", random1025b},
	{"random_32kb.bin", random32kb},
	{"random_512kb.bin", random512kb},
	{"random_1mb.bin", random1mb},
	{"small_file.txt", smallFile},
	{"users.json", usersJson},
	{"users_pretty.json", usersJsonPretty},
}

var testFilesShort = []testFile{
	{"random_1024b.bin", random1024b},
	{"users_pretty.json", usersJsonPretty},
}

var testFilesTable = []testFile{
	{"random_512b.bin", random512b},
	{"random_1023b.bin", random1023b},
	{"random_1024b.bin", random1024b},
	{"random_1025b.bin", random1025b},
	{"random_32kb.bin", random32kb},
	{"random_512kb.bin", random512kb},
	{"random_1mb.bin", random1mb},
	{"small_file.txt", smallFile},
	{"users.json", usersJson},
	{"users_pretty.json", usersJsonPretty},
}
