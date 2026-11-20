// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

//! A custom [`LocationGeneratorFactory`] for tests.

use crate::spec::PartitionKey;
use crate::writer::file_writer::location_generator::{
    JAVA_LOCATION_PROVIDER_IMPL, LocationGenerator, LocationGeneratorContext,
    LocationGeneratorFactory, ResolvingLocationGeneratorFactory, TableLocationGenerator,
};
use crate::{Error, ErrorKind, Result};

/// The Java location provider class that [`JavaLocationProviderFactory`] supports.
pub(crate) const CUSTOM_LOCATION_PROVIDER: &str = "org.example.CustomLocationProvider";

/// Places every data file directly under `memory:///custom/{namespace}/{table}`.
#[derive(Clone)]
struct CustomLocationGenerator {
    base: String,
}

impl LocationGenerator for CustomLocationGenerator {
    fn generate_location(&self, _partition_key: Option<&PartitionKey>, file_name: &str) -> String {
        format!("{}/{file_name}", self.base)
    }
}

/// Maps Java's `write.location-provider.impl` to Rust location generators.
///
/// Tables naming [`CUSTOM_LOCATION_PROVIDER`] get a custom layout, tables that name no provider
/// get the built-in layout, and other providers are rejected with
/// [`ErrorKind::FeatureUnsupported`].
#[derive(Debug)]
pub(crate) struct JavaLocationProviderFactory;

impl LocationGeneratorFactory for JavaLocationProviderFactory {
    fn create_location_generator(
        &self,
        context: &LocationGeneratorContext<'_>,
    ) -> Result<TableLocationGenerator> {
        let provider = context
            .metadata()
            .properties()
            .get(JAVA_LOCATION_PROVIDER_IMPL);
        match provider.map(String::as_str) {
            None => ResolvingLocationGeneratorFactory.create_location_generator(context),
            Some(CUSTOM_LOCATION_PROVIDER) => {
                let identifier = context.identifier();
                Ok(TableLocationGenerator::new(CustomLocationGenerator {
                    base: format!(
                        "memory:///custom/{}/{}",
                        identifier.namespace().join("/"),
                        identifier.name()
                    ),
                }))
            }
            Some(provider) => Err(Error::new(
                ErrorKind::FeatureUnsupported,
                format!("Location provider {provider} is not supported"),
            )),
        }
    }
}
