use crate::event::Event;
use crate::schema::create_intermediate_schema;
use anyhow::{Context as _, Result};
use arrow::{
    array::{
        ArrayRef, Int32Builder, Int64Builder, StringBuilder, UInt32Builder, UInt64Builder,
        UInt8Builder,
    },
    datatypes::Schema,
    record_batch::RecordBatch,
};
use log::debug;
use parquet::{
    arrow::ArrowWriter,
    basic::Compression,
    file::{metadata::KeyValue, properties::WriterProperties},
};
use std::fs::File;
use std::sync::Arc;

/// Batch size for Parquet writes (10,000 events per batch)
pub const BATCH_SIZE: usize = 10_000;
pub const PARQUET_METADATA_SAMPLE_FREQ_HZ_KEY: &str = "probex.sample_freq_hz";
pub const PARQUET_METADATA_STACK_TRACE_FORMAT_KEY: &str = "probex.stack_trace_format";
pub const STACK_TRACE_FORMAT_SYMBOLIZED_V1: &str = "symbolized_v1";

/// Parquet batch writer that buffers events and writes them in batches
/// to minimize memory usage and improve write efficiency.
pub struct ParquetBatchWriter {
    writer: ArrowWriter<File>,
    schema: Arc<Schema>,
    batch: Vec<Event>,
    total_written: usize,
}

impl ParquetBatchWriter {
    /// Create a new ParquetBatchWriter that writes to the specified file
    pub fn new(path: &str, sample_freq_hz: u64) -> Result<Self> {
        let schema = Arc::new(create_intermediate_schema());
        let file =
            File::create(path).with_context(|| format!("failed to create output file {}", path))?;

        let key_value_metadata = vec![KeyValue::new(
            PARQUET_METADATA_SAMPLE_FREQ_HZ_KEY.to_string(),
            sample_freq_hz.to_string(),
        )];
        let props = WriterProperties::builder()
            .set_compression(Compression::SNAPPY)
            .set_key_value_metadata(Some(key_value_metadata))
            .build();

        let writer = ArrowWriter::try_new(file, schema.clone(), Some(props))
            .with_context(|| "failed to create Parquet writer")?;

        Ok(Self {
            writer,
            schema,
            batch: Vec::with_capacity(BATCH_SIZE),
            total_written: 0,
        })
    }

    /// Push an event to the batch. Automatically flushes when batch is full.
    pub fn push(&mut self, event: Event) -> Result<()> {
        self.batch.push(event);
        if self.batch.len() >= BATCH_SIZE {
            self.flush_batch()?;
        }
        Ok(())
    }

    /// Flush the current batch to the Parquet file
    pub fn flush_batch(&mut self) -> Result<()> {
        if self.batch.is_empty() {
            return Ok(());
        }

        let batch_len = self.batch.len();

        // Build Arrow arrays from the batch
        let mut event_type_builder = StringBuilder::with_capacity(batch_len, batch_len * 20);
        let mut ts_ns_builder = UInt64Builder::with_capacity(batch_len);
        let mut pid_builder = UInt32Builder::with_capacity(batch_len);
        let mut tgid_builder = UInt32Builder::with_capacity(batch_len);
        let mut process_name_builder = StringBuilder::with_capacity(batch_len, batch_len * 24);
        let mut stack_id_builder = Int32Builder::with_capacity(batch_len);
        let mut kernel_stack_id_builder = Int32Builder::with_capacity(batch_len);
        let mut stack_kind_builder = StringBuilder::with_capacity(batch_len, batch_len * 8);
        let mut stack_frames_builder = StringBuilder::with_capacity(batch_len, batch_len * 64);
        let mut stack_trace_builder = StringBuilder::with_capacity(batch_len, batch_len * 48);
        let mut cpu_builder = UInt8Builder::with_capacity(batch_len);
        let mut prev_pid_builder = UInt32Builder::with_capacity(batch_len);
        let mut next_pid_builder = UInt32Builder::with_capacity(batch_len);
        let mut prev_state_builder = Int64Builder::with_capacity(batch_len);
        let mut parent_pid_builder = UInt32Builder::with_capacity(batch_len);
        let mut child_pid_builder = UInt32Builder::with_capacity(batch_len);
        let mut exit_code_builder = Int32Builder::with_capacity(batch_len);
        let mut address_builder = UInt64Builder::with_capacity(batch_len);
        let mut error_code_builder = UInt64Builder::with_capacity(batch_len);
        let mut fd_builder = Int64Builder::with_capacity(batch_len);
        let mut count_builder = UInt64Builder::with_capacity(batch_len);
        let mut ret_builder = Int64Builder::with_capacity(batch_len);
        let mut submit_ts_ns_builder = UInt64Builder::with_capacity(batch_len);
        let mut io_uring_opcode_builder = UInt8Builder::with_capacity(batch_len);
        let mut io_uring_res_builder = Int32Builder::with_capacity(batch_len);

        for event in self.batch.drain(..) {
            event_type_builder.append_value(event.event_type);
            ts_ns_builder.append_value(event.ts_ns);
            pid_builder.append_value(event.pid);
            tgid_builder.append_value(event.tgid);
            process_name_builder.append_option(event.process_name.as_deref());
            stack_id_builder.append_option(event.stack_id);
            kernel_stack_id_builder.append_option(event.kernel_stack_id);
            stack_kind_builder.append_option(event.stack_kind);
            stack_frames_builder.append_option(event.stack_frames.as_deref());
            stack_trace_builder.append_option(event.stack_trace.as_deref());
            cpu_builder.append_value(event.cpu);
            prev_pid_builder.append_option(event.prev_pid);
            next_pid_builder.append_option(event.next_pid);
            prev_state_builder.append_option(event.prev_state);
            parent_pid_builder.append_option(event.parent_pid);
            child_pid_builder.append_option(event.child_pid);
            exit_code_builder.append_option(event.exit_code);
            address_builder.append_option(event.address);
            error_code_builder.append_option(event.error_code);
            fd_builder.append_option(event.fd);
            count_builder.append_option(event.count);
            ret_builder.append_option(event.ret);
            submit_ts_ns_builder.append_option(event.submit_ts_ns);
            io_uring_opcode_builder.append_option(event.io_uring_opcode);
            io_uring_res_builder.append_option(event.io_uring_res);
        }

        let columns: Vec<ArrayRef> = vec![
            Arc::new(event_type_builder.finish()),
            Arc::new(ts_ns_builder.finish()),
            Arc::new(pid_builder.finish()),
            Arc::new(tgid_builder.finish()),
            Arc::new(process_name_builder.finish()),
            Arc::new(stack_id_builder.finish()),
            Arc::new(kernel_stack_id_builder.finish()),
            Arc::new(stack_kind_builder.finish()),
            Arc::new(stack_frames_builder.finish()),
            Arc::new(stack_trace_builder.finish()),
            Arc::new(cpu_builder.finish()),
            Arc::new(prev_pid_builder.finish()),
            Arc::new(next_pid_builder.finish()),
            Arc::new(prev_state_builder.finish()),
            Arc::new(parent_pid_builder.finish()),
            Arc::new(child_pid_builder.finish()),
            Arc::new(exit_code_builder.finish()),
            Arc::new(address_builder.finish()),
            Arc::new(error_code_builder.finish()),
            Arc::new(fd_builder.finish()),
            Arc::new(count_builder.finish()),
            Arc::new(ret_builder.finish()),
            Arc::new(submit_ts_ns_builder.finish()),
            Arc::new(io_uring_opcode_builder.finish()),
            Arc::new(io_uring_res_builder.finish()),
        ];

        let record_batch = RecordBatch::try_new(self.schema.clone(), columns)
            .with_context(|| "failed to create record batch")?;

        self.writer
            .write(&record_batch)
            .with_context(|| "failed to write record batch")?;

        self.total_written += batch_len;
        debug!(
            "Flushed {} events to Parquet (total: {})",
            batch_len, self.total_written
        );

        Ok(())
    }

    /// Finish writing and close the file. Returns total events written.
    pub fn finish(mut self) -> Result<usize> {
        self.flush_batch()?;
        self.writer
            .close()
            .with_context(|| "failed to close Parquet writer")?;
        Ok(self.total_written)
    }
}
