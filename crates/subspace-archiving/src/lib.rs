// Copyright (C) 2021 Subspace Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Collection of modules used for dealing with archived state of Subspace Network.
#![cfg_attr(not(feature = "std"), no_std)]
#![feature(array_chunks, drain_filter, iter_collect_into, slice_flatten)]

pub mod archiver;
pub mod piece_reconstructor;
pub mod reconstructor;
