// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2026 Oxide Computer Company

// macOS xtask stub – packaging is not implemented for macOS.

use anyhow::anyhow;

use crate::DistFormat;

pub async fn dist(_release: bool, _format: DistFormat) -> anyhow::Result<()> {
    Err(anyhow!("dist is not implemented on macOS"))
}
