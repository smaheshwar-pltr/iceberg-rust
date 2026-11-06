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

//! Table API for Apache Iceberg

use std::sync::Arc;

use crate::arrow::ArrowReaderBuilder;
use crate::encryption::EncryptionManager;
use crate::encryption::kms::KeyManagementClient;
use crate::error::invalid_data;
use crate::inspect::MetadataTable;
use crate::io::FileIO;
use crate::io::object_cache::ObjectCache;
use crate::runtime::Runtime;
use crate::scan::TableScanBuilder;
use crate::spec::{
    ManifestListReader, ManifestReader, SchemaRef, SnapshotRef, TableMetadata, TableMetadataRef,
};
use crate::writer::base_writer::data_file_writer::DataFileWriterBuilder;
use crate::writer::file_writer::location_generator::{FileNameGenerator, TableLocationGenerator};
use crate::writer::file_writer::rolling_writer::RollingFileWriterBuilder;
use crate::writer::file_writer::{FileWriterBuilder, ParquetWriterBuilder};
use crate::{Result, TableIdent};

/// Builder to create table scan.
pub struct TableBuilder {
    file_io: Option<FileIO>,
    metadata_location: Option<String>,
    metadata: Option<TableMetadataRef>,
    identifier: Option<TableIdent>,
    kms_client: Option<Arc<dyn KeyManagementClient>>,
    readonly: bool,
    disable_cache: bool,
    cache_size_bytes: Option<u64>,
    runtime: Option<Runtime>,
}

impl TableBuilder {
    pub(crate) fn new() -> Self {
        Self {
            file_io: None,
            metadata_location: None,
            metadata: None,
            identifier: None,
            kms_client: None,
            readonly: false,
            disable_cache: false,
            cache_size_bytes: None,
            runtime: None,
        }
    }

    /// required - sets the necessary FileIO to use for the table
    pub fn file_io(mut self, file_io: FileIO) -> Self {
        self.file_io = Some(file_io);
        self
    }

    /// optional - sets the tables metadata location
    pub fn metadata_location<T: Into<String>>(mut self, metadata_location: T) -> Self {
        self.metadata_location = Some(metadata_location.into());
        self
    }

    /// required - passes in the TableMetadata to use for the Table
    pub fn metadata<T: Into<TableMetadataRef>>(mut self, metadata: T) -> Self {
        self.metadata = Some(metadata.into());
        self
    }

    /// required - passes in the TableIdent to use for the Table
    pub fn identifier(mut self, identifier: TableIdent) -> Self {
        self.identifier = Some(identifier);
        self
    }

    /// specifies if the Table is readonly or not (default not)
    pub fn readonly(mut self, readonly: bool) -> Self {
        self.readonly = readonly;
        self
    }

    /// specifies if the Table's metadata cache will be disabled,
    /// so that reads of Manifests and ManifestLists will never
    /// get cached.
    pub fn disable_cache(mut self) -> Self {
        self.disable_cache = true;
        self
    }

    /// optionally set a non-default metadata cache size
    pub fn cache_size_bytes(mut self, cache_size_bytes: u64) -> Self {
        self.cache_size_bytes = Some(cache_size_bytes);
        self
    }

    /// Set the Runtime for this table to use when spawning tasks.
    pub fn runtime(mut self, runtime: Runtime) -> Self {
        self.runtime = Some(runtime);
        self
    }

    /// optional - sets the KMS client used to unwrap keys for table encryption.
    ///
    /// If the table metadata has the `encryption.key-id` property set, a
    /// [`KeyManagementClient`] must be provided here so the table can build
    /// an [`EncryptionManager`]; otherwise [`Self::build`] will return an error.
    pub fn kms_client(mut self, kms_client: Arc<dyn KeyManagementClient>) -> Self {
        self.kms_client = Some(kms_client);
        self
    }

    /// build the Table
    pub fn build(self) -> Result<Table> {
        let Self {
            file_io,
            metadata_location,
            metadata,
            identifier,
            kms_client,
            readonly,
            disable_cache,
            cache_size_bytes,
            runtime,
        } = self;

        let Some(file_io) = file_io else {
            return Err(invalid_data!(
                "FileIO must be provided with TableBuilder.file_io()"
            ));
        };

        let Some(metadata) = metadata else {
            return Err(invalid_data!(
                "TableMetadataRef must be provided with TableBuilder.metadata()"
            ));
        };

        let Some(identifier) = identifier else {
            return Err(invalid_data!(
                "TableIdent must be provided with TableBuilder.identifier()"
            ));
        };

        let Some(runtime) = runtime else {
            return Err(invalid_data!(
                "Runtime must be provided with TableBuilder.runtime()"
            ));
        };

        let encryption_manager =
            EncryptionManager::from_table_metadata(kms_client.as_ref(), &metadata)?;

        let object_cache = if disable_cache {
            Arc::new(ObjectCache::with_disabled_cache(
                file_io.clone(),
                encryption_manager.clone(),
            ))
        } else if let Some(cache_size_bytes) = cache_size_bytes {
            Arc::new(ObjectCache::new_with_capacity(
                file_io.clone(),
                cache_size_bytes,
                encryption_manager.clone(),
            ))
        } else {
            Arc::new(ObjectCache::new(
                file_io.clone(),
                encryption_manager.clone(),
            ))
        };

        Ok(Table {
            file_io,
            metadata_location,
            metadata,
            identifier,
            readonly,
            object_cache,
            runtime,
            encryption_manager,
        })
    }
}

/// Table represents a table in the catalog.
#[derive(Debug, Clone)]
pub struct Table {
    file_io: FileIO,
    metadata_location: Option<String>,
    metadata: TableMetadataRef,
    identifier: TableIdent,
    readonly: bool,
    object_cache: Arc<ObjectCache>,
    runtime: Runtime,
    encryption_manager: Option<Arc<EncryptionManager>>,
}

impl Table {
    /// Sets the [`Table`] metadata and returns an updated instance with the new metadata applied.
    pub(crate) fn with_metadata(mut self, metadata: TableMetadataRef) -> Self {
        self.metadata = metadata;
        self
    }

    /// Sets the [`Table`] metadata location and returns an updated instance.
    pub(crate) fn with_metadata_location(mut self, metadata_location: String) -> Self {
        self.metadata_location = Some(metadata_location);
        self
    }

    /// Returns this table bound to `runtime`, sharing its manifest cache.
    ///
    /// Tasks such as scan planning and reads are spawned on `runtime`. A table rebuilt
    /// through [`Table::builder`] starts with an empty cache.
    pub fn with_runtime(mut self, runtime: Runtime) -> Self {
        self.runtime = runtime;
        self
    }

    /// Returns a TableBuilder to build a table
    pub fn builder() -> TableBuilder {
        TableBuilder::new()
    }

    /// Returns table identifier.
    pub fn identifier(&self) -> &TableIdent {
        &self.identifier
    }
    /// Returns current metadata.
    pub fn metadata(&self) -> &TableMetadata {
        &self.metadata
    }

    /// Returns current metadata ref.
    pub fn metadata_ref(&self) -> TableMetadataRef {
        self.metadata.clone()
    }

    /// Returns current metadata location.
    pub fn metadata_location(&self) -> Option<&str> {
        self.metadata_location.as_deref()
    }

    /// Returns current metadata location in a result.
    pub fn metadata_location_result(&self) -> Result<&str> {
        self.metadata_location.as_deref().ok_or(invalid_data!(
            "Metadata location does not exist for table: {}",
            self.identifier
        ))
    }

    /// Returns file io used in this table.
    pub fn file_io(&self) -> &FileIO {
        &self.file_io
    }

    /// Returns this table's object cache
    pub(crate) fn object_cache(&self) -> Arc<ObjectCache> {
        self.object_cache.clone()
    }

    /// Returns the [`EncryptionManager`] for this table, if encryption is
    /// configured.
    ///
    /// A manager is present iff the table metadata has the
    /// `encryption.key-id` property set and a [`KeyManagementClient`] was
    /// supplied to the [`TableBuilder`].
    pub fn encryption_manager(&self) -> Option<&Arc<EncryptionManager>> {
        self.encryption_manager.as_ref()
    }

    /// Creates a table scan.
    pub fn scan(&self) -> TableScanBuilder<'_> {
        TableScanBuilder::new(self)
    }

    /// Creates a metadata table which provides table-like APIs for inspecting metadata.
    /// See [`MetadataTable`] for more details.
    pub fn inspect(&self) -> MetadataTable<'_> {
        MetadataTable::new(self)
    }

    /// Returns the [`Runtime`] for this table.
    pub(crate) fn runtime(&self) -> &Runtime {
        &self.runtime
    }

    /// Returns the flag indicating whether the `Table` is readonly or not
    pub fn readonly(&self) -> bool {
        self.readonly
    }

    /// Returns the current schema as a shared reference.
    pub fn current_schema_ref(&self) -> SchemaRef {
        self.metadata.current_schema().clone()
    }

    /// Creates a [`ManifestListReader`] for the given snapshot.
    pub fn manifest_list_reader(&self, snapshot: &SnapshotRef) -> ManifestListReader {
        ManifestListReader::new(
            snapshot.clone(),
            self.file_io.clone(),
            self.metadata.clone(),
            self.encryption_manager.clone(),
        )
    }

    /// Creates a [`ManifestReader`] for loading manifests referenced by this table.
    pub fn manifest_reader(&self) -> ManifestReader {
        ManifestReader::new(self.file_io.clone())
    }

    /// Create a reader for the table.
    pub fn reader_builder(&self) -> ArrowReaderBuilder {
        ArrowReaderBuilder::new(self.file_io.clone(), self.runtime().clone())
    }

    /// Creates a [`ParquetWriterBuilder`] for writing files into this table.
    ///
    /// The writer properties come from the table's `write.parquet.*` properties, as in
    /// [`ParquetWriterBuilder::from_table_properties`]. If the table has an
    /// [`EncryptionManager`], it is attached, so files written for an encrypted table are
    /// encrypted.
    ///
    /// This does not check `write.format.default`. Callers that write in the table's default
    /// format must check that it is parquet.
    pub fn parquet_writer_builder(&self, schema: SchemaRef) -> Result<ParquetWriterBuilder> {
        let mut builder =
            ParquetWriterBuilder::from_table_properties(&self.metadata.table_properties(), schema)?;
        if let Some(encryption_manager) = &self.encryption_manager {
            builder = builder.with_encryption_manager(encryption_manager.clone());
        }
        Ok(builder)
    }

    /// Creates a [`DataFileWriterBuilder`] for writing data files into this table.
    ///
    /// Files are written through the table's [`FileIO`], rolled over at
    /// `write.target-file-size-bytes`, and placed in the table's location layout (see
    /// [`TableLocationGenerator`]).
    ///
    /// This does not configure the file format. The file format, its settings and encryption
    /// all come from `inner_builder`. For parquet, build it with
    /// [`Self::parquet_writer_builder`]. A builder from [`ParquetWriterBuilder::new`] or
    /// [`ParquetWriterBuilder::from_table_properties`] writes plaintext files even if the table
    /// is encrypted.
    pub fn data_file_writer_builder<B, F>(
        &self,
        inner_builder: B,
        file_name_generator: F,
    ) -> Result<DataFileWriterBuilder<B, TableLocationGenerator, F>>
    where
        B: FileWriterBuilder,
        F: FileNameGenerator,
    {
        let table_props = self.metadata.table_properties();
        Ok(DataFileWriterBuilder::new(RollingFileWriterBuilder::new(
            inner_builder,
            table_props.write_target_file_size_bytes()?,
            self.file_io.clone(),
            TableLocationGenerator::new(&self.metadata)?,
            file_name_generator,
        )))
    }
}

/// `StaticTable` is a read-only table struct that can be created from a metadata file or from `TableMetaData` without a catalog.
/// It can only be used to read metadata and for table scan.
/// # Examples
///
/// ```rust, no_run
/// # use iceberg::io::FileIO;
/// # use iceberg::table::StaticTable;
/// # use iceberg::TableIdent;
/// # async fn example() {
/// let metadata_file_location = "s3://bucket_name/path/to/metadata.json";
/// let file_io = FileIO::new_with_fs();
/// let static_identifier = TableIdent::from_strs(["static_ns", "static_table"]).unwrap();
/// let static_table =
///     StaticTable::from_metadata_file(&metadata_file_location, static_identifier, file_io)
///         .await
///         .unwrap();
/// let snapshot_id = static_table
///     .metadata()
///     .current_snapshot()
///     .unwrap()
///     .snapshot_id();
/// # }
/// ```
#[derive(Debug, Clone)]
pub struct StaticTable(Table);

impl StaticTable {
    /// Creates a static table from a given `TableMetadata` and `FileIO`
    pub async fn from_metadata(
        metadata: TableMetadata,
        table_ident: TableIdent,
        file_io: FileIO,
    ) -> Result<Self> {
        let table = Table::builder()
            .metadata(metadata)
            .identifier(table_ident)
            .file_io(file_io.clone())
            .runtime(Runtime::try_current()?)
            .readonly(true)
            .build();

        Ok(Self(table?))
    }
    /// Creates a static table directly from metadata file and `FileIO`
    pub async fn from_metadata_file(
        metadata_location: &str,
        table_ident: TableIdent,
        file_io: FileIO,
    ) -> Result<Self> {
        let metadata = TableMetadata::read_from(&file_io, metadata_location).await?;

        let table = Table::builder()
            .metadata(metadata)
            .metadata_location(metadata_location)
            .identifier(table_ident)
            .file_io(file_io.clone())
            .runtime(Runtime::try_current()?)
            .readonly(true)
            .build();

        Ok(Self(table?))
    }

    /// Create a TableScanBuilder for the static table.
    pub fn scan(&self) -> TableScanBuilder<'_> {
        self.0.scan()
    }

    /// Get TableMetadataRef for the static table
    pub fn metadata(&self) -> TableMetadataRef {
        self.0.metadata_ref()
    }

    /// Consumes the `StaticTable` and return it as a `Table`
    /// Please use this method carefully as the Table it returns remains detached from a catalog
    /// and can't be used to perform modifications on the table.
    pub fn into_table(self) -> Table {
        self.0
    }

    /// Create a reader for the table.
    pub fn reader_builder(&self) -> ArrowReaderBuilder {
        self.0.reader_builder()
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use arrow_array::{Int64Array, RecordBatch};
    use bytes::Bytes;
    use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
    use parquet::basic::Compression;

    use super::*;
    use crate::ErrorKind;
    use crate::arrow::schema_to_arrow_schema;
    use crate::encryption::SensitiveBytes;
    use crate::encryption::kms::MemoryKeyManagementClient;
    use crate::spec::{DataFile, DataFileFormat, TableProperties};
    use crate::test_utils::make_encrypted_table;
    use crate::writer::file_writer::location_generator::{
        DefaultFileNameGenerator, LocationGenerator, ObjectStorageLocationGenerator,
    };
    use crate::writer::{IcebergWriter, IcebergWriterBuilder};

    fn load_test_metadata(filename: &str) -> TableMetadata {
        let path = format!(
            "{}/testdata/table_metadata/{}",
            env!("CARGO_MANIFEST_DIR"),
            filename
        );
        let json = fs::read_to_string(path).unwrap();
        serde_json::from_str(&json).unwrap()
    }

    #[tokio::test]
    async fn test_static_table_from_file() {
        let metadata_file_name = "TableMetadataV2Valid.json";
        let metadata_file_path = format!(
            "{}/testdata/table_metadata/{}",
            env!("CARGO_MANIFEST_DIR"),
            metadata_file_name
        );
        let file_io = FileIO::new_with_fs();
        let static_identifier = TableIdent::from_strs(["static_ns", "static_table"]).unwrap();
        let static_table =
            StaticTable::from_metadata_file(&metadata_file_path, static_identifier, file_io)
                .await
                .unwrap();
        let snapshot_id = static_table
            .metadata()
            .current_snapshot()
            .unwrap()
            .snapshot_id();
        assert_eq!(
            snapshot_id, 3055729675574597004,
            "snapshot id from metadata don't match"
        );
    }

    #[tokio::test]
    async fn test_static_into_table() {
        let metadata_file_name = "TableMetadataV2Valid.json";
        let metadata_file_path = format!(
            "{}/testdata/table_metadata/{}",
            env!("CARGO_MANIFEST_DIR"),
            metadata_file_name
        );
        let file_io = FileIO::new_with_fs();
        let static_identifier = TableIdent::from_strs(["static_ns", "static_table"]).unwrap();
        let static_table =
            StaticTable::from_metadata_file(&metadata_file_path, static_identifier, file_io)
                .await
                .unwrap();
        let table = static_table.into_table();
        assert!(table.readonly());
        assert_eq!(table.identifier.name(), "static_table");
        assert_eq!(
            table.metadata_location(),
            Some(metadata_file_path).as_deref()
        );
    }

    #[tokio::test]
    async fn test_table_readonly_flag() {
        let metadata_file_name = "TableMetadataV2Valid.json";
        let metadata_file_path = format!(
            "{}/testdata/table_metadata/{}",
            env!("CARGO_MANIFEST_DIR"),
            metadata_file_name
        );
        let file_io = FileIO::new_with_fs();
        let metadata_file = file_io.new_input(metadata_file_path).unwrap();
        let metadata_file_content = metadata_file.read().await.unwrap();
        let table_metadata =
            serde_json::from_slice::<TableMetadata>(&metadata_file_content).unwrap();
        let static_identifier = TableIdent::from_strs(["ns", "table"]).unwrap();
        let table = Table::builder()
            .metadata(table_metadata)
            .identifier(static_identifier)
            .file_io(file_io.clone())
            .runtime(Runtime::try_current().unwrap())
            .build()
            .unwrap();
        assert!(!table.readonly());
        assert_eq!(table.identifier.name(), "table");
    }

    #[tokio::test]
    async fn test_table_with_runtime_moves_work_and_keeps_object_cache() {
        let old = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        let table = Table::builder()
            .metadata(load_test_metadata("TableMetadataV2Valid.json"))
            .identifier(TableIdent::from_strs(["ns", "table"]).unwrap())
            .file_io(FileIO::new_with_memory())
            .runtime(Runtime::new(&old))
            .build()
            .unwrap();
        // With the old runtime shut down, the spawn below succeeds only if
        // `rebound` uses the new one.
        old.shutdown_background();

        let rebound = table.clone().with_runtime(Runtime::try_current().unwrap());

        assert!(Arc::ptr_eq(&table.object_cache(), &rebound.object_cache()));
        assert_eq!(
            rebound.runtime().io().spawn(async { 42 }).await.unwrap(),
            42
        );
    }

    fn make_kms() -> Arc<dyn KeyManagementClient> {
        let kms = MemoryKeyManagementClient::new();
        kms.add_master_key("master-1").unwrap();
        Arc::new(kms)
    }

    #[tokio::test]
    async fn table_decrypts_manifest_list_via_object_cache() {
        // The fixture contains a snapshot with key-id, encryption-keys (KEK + wrapped DEK),
        // all generated with the master key bytes below.
        let mut metadata: TableMetadata = load_test_metadata("TableMetadataV3ValidEncryption.json");

        // Point the snapshot's manifest-list at the testdata file on disk.
        let manifest_list_path = format!(
            "{}/testdata/manifests_lists/manifest-list-v3-encrypted.avro",
            env!("CARGO_MANIFEST_DIR"),
        );
        let snapshot = metadata.snapshots.get_mut(&1).unwrap();
        let mut patched = snapshot.as_ref().clone();
        patched.manifest_list = manifest_list_path;
        *snapshot = Arc::new(patched);

        // Seed the KMS with the same master key bytes used to generate the fixture.
        let kms: Arc<dyn KeyManagementClient> = {
            let k = MemoryKeyManagementClient::new();
            k.add_master_key_bytes(
                "master-1",
                SensitiveBytes::new([
                    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
                    0x0d, 0x0e, 0x0f,
                ]),
            )
            .unwrap();
            Arc::new(k)
        };

        let table = Table::builder()
            .file_io(FileIO::new_with_fs())
            .metadata(metadata)
            .identifier(TableIdent::from_strs(["ns", "enc"]).unwrap())
            .kms_client(kms)
            .runtime(Runtime::try_current().unwrap())
            .build()
            .unwrap();

        let snapshot_ref = table.metadata().current_snapshot().unwrap();
        let manifest_list = table
            .object_cache()
            .get_manifest_list(snapshot_ref, &table.metadata_ref())
            .await
            .unwrap();
        assert_eq!(manifest_list.entries().len(), 0);
    }

    #[tokio::test]
    async fn table_builder_errors_when_encryption_key_id_set_but_no_kms() {
        let metadata: TableMetadata = load_test_metadata("TableMetadataV3ValidEncryption.json");

        let err = Table::builder()
            .file_io(FileIO::new_with_memory())
            .metadata(metadata)
            .identifier(TableIdent::from_strs(["ns", "enc"]).unwrap())
            .runtime(Runtime::try_current().unwrap())
            .build()
            .unwrap_err();
        assert_eq!(err.kind(), ErrorKind::PreconditionFailed);
    }

    #[tokio::test]
    async fn table_builder_skips_encryption_on_pre_v3_table() {
        // Encryption is a v3 spec feature; pre-v3 tables silently skip
        // encryption even if encryption.key-id is set.
        let mut metadata: TableMetadata = load_test_metadata("TableMetadataV2ValidMinimal.json");
        metadata.properties.insert(
            TableProperties::PROPERTY_ENCRYPTION_KEY_ID.to_string(),
            "master-1".to_string(),
        );

        let table = Table::builder()
            .file_io(FileIO::new_with_memory())
            .metadata(metadata)
            .identifier(TableIdent::from_strs(["ns", "enc"]).unwrap())
            .kms_client(make_kms())
            .runtime(Runtime::try_current().unwrap())
            .build()
            .unwrap();
        assert!(table.encryption_manager().is_none());
    }

    #[tokio::test]
    async fn table_builder_skips_encryption_when_property_absent() {
        let metadata: TableMetadata = load_test_metadata("TableMetadataV3ValidMinimal.json");
        let table = Table::builder()
            .file_io(FileIO::new_with_memory())
            .metadata(metadata)
            .identifier(TableIdent::from_strs(["ns", "plain"]).unwrap())
            .kms_client(make_kms())
            .runtime(Runtime::try_current().unwrap())
            .build()
            .unwrap();
        assert!(table.encryption_manager().is_none());
    }

    /// A table at `memory:///table` with an unpartitioned `x: long` schema, no encryption and the
    /// given properties.
    fn memory_table(properties: &[(&str, &str)]) -> Table {
        let mut metadata: TableMetadata = load_test_metadata("TableMetadataV3ValidEncryption.json");
        metadata.properties = properties
            .iter()
            .map(|(key, value)| (key.to_string(), value.to_string()))
            .collect();
        Table::builder()
            .file_io(FileIO::new_with_memory())
            .metadata(metadata)
            .identifier(TableIdent::from_strs(["ns", "plain"]).unwrap())
            .runtime(Runtime::try_current().unwrap())
            .build()
            .unwrap()
    }

    /// Writes `num_batches` batches of 100 rows through the table's writer builders.
    async fn write_with_table_builders(table: &Table, num_batches: i64) -> Vec<DataFile> {
        let schema = table.current_schema_ref();
        let arrow_schema = Arc::new(schema_to_arrow_schema(&schema).unwrap());
        let parquet_writer_builder = table.parquet_writer_builder(schema).unwrap();
        let file_name_generator =
            DefaultFileNameGenerator::new("test".to_string(), None, DataFileFormat::Parquet);
        let mut writer = table
            .data_file_writer_builder(parquet_writer_builder, file_name_generator)
            .unwrap()
            .build(None)
            .await
            .unwrap();
        for i in 0..num_batches {
            let column = Int64Array::from_iter_values(i * 100..(i + 1) * 100);
            let batch = RecordBatch::try_new(arrow_schema.clone(), vec![Arc::new(column)]).unwrap();
            writer.write(batch).await.unwrap();
        }
        writer.close().await.unwrap()
    }

    async fn read_file(table: &Table, data_file: &DataFile) -> Bytes {
        let input = table.file_io().new_input(data_file.file_path()).unwrap();
        input.read().await.unwrap()
    }

    #[tokio::test]
    async fn parquet_writer_builder_applies_write_parquet_properties() {
        let table = memory_table(&[(TableProperties::PROPERTY_PARQUET_COMPRESSION_CODEC, "gzip")]);

        let data_files = write_with_table_builders(&table, 1).await;

        assert_eq!(data_files.len(), 1);
        assert!(data_files[0].key_metadata().is_none());
        let reader =
            ParquetRecordBatchReaderBuilder::try_new(read_file(&table, &data_files[0]).await)
                .unwrap();
        let compression = reader.metadata().row_group(0).column(0).compression();
        assert!(
            matches!(compression, Compression::GZIP(_)),
            "{compression:?}"
        );
    }

    #[tokio::test]
    async fn parquet_writer_builder_rejects_invalid_write_parquet_property() {
        let table = memory_table(&[(TableProperties::PROPERTY_PARQUET_COMPRESSION_CODEC, "bogus")]);

        let err = table
            .parquet_writer_builder(table.current_schema_ref())
            .unwrap_err();

        assert_eq!(err.kind(), ErrorKind::DataInvalid);
    }

    #[tokio::test]
    async fn parquet_writer_builder_encrypts_files_for_encrypted_table() {
        let table = make_encrypted_table().await;

        let data_files = write_with_table_builders(&table, 1).await;

        assert_eq!(data_files.len(), 1);
        assert!(data_files[0].key_metadata().is_some());
        // A reader without the table's keys cannot read the file.
        let plaintext_read =
            ParquetRecordBatchReaderBuilder::try_new(read_file(&table, &data_files[0]).await)
                .and_then(|builder| builder.build())
                .map(|reader| reader.collect::<std::result::Result<Vec<_>, _>>());
        assert!(!matches!(plaintext_read, Ok(Ok(_))));
    }

    #[tokio::test]
    async fn data_file_writer_builder_follows_table_layout_and_target_file_size() {
        let table = memory_table(&[
            (
                TableProperties::PROPERTY_WRITE_OBJECT_STORAGE_ENABLED,
                "true",
            ),
            (TableProperties::PROPERTY_WRITE_TARGET_FILE_SIZE_BYTES, "1"),
        ]);

        let data_files = write_with_table_builders(&table, 3).await;

        // With the default target file size, all rows would go to one file.
        assert!(data_files.len() > 1, "{data_files:?}");
        let record_count: u64 = data_files.iter().map(DataFile::record_count).sum();
        assert_eq!(record_count, 300);
        let object_storage = ObjectStorageLocationGenerator::new(table.metadata()).unwrap();
        for data_file in &data_files {
            let path = data_file.file_path();
            let file_name = path.rsplit('/').next().unwrap();
            assert_eq!(path, object_storage.generate_location(None, file_name));
            assert!(table.file_io().exists(path).await.unwrap(), "{path}");
        }
    }
}
