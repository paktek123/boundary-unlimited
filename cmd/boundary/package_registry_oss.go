// Copyright IBM Corp. 2020, 2026
// SPDX-License-Identifier: BUSL-1.1

package main

import (
	// Enable tcp, ssh and rdp target support.
	_ "github.com/hashicorp/boundary/internal/daemon/controller/handlers/targets/rdp"
	_ "github.com/hashicorp/boundary/internal/daemon/controller/handlers/targets/ssh"
	_ "github.com/hashicorp/boundary/internal/daemon/controller/handlers/targets/tcp"
	_ "github.com/hashicorp/boundary/internal/target/rdp"
	_ "github.com/hashicorp/boundary/internal/target/ssh"
	_ "github.com/hashicorp/boundary/internal/target/tcp"
)
