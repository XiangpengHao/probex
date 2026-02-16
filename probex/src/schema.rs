use arrow::datatypes::{DataType, Field, Schema};
use std::sync::Arc;

/// Creates the Arrow schema for the temporary event table before stack finalization.
pub fn create_intermediate_schema() -> Schema {
    Schema::new(vec![
        Field::new("event_type", DataType::Utf8, false),
        Field::new("ts_ns", DataType::UInt64, false),
        Field::new("pid", DataType::UInt32, false),
        Field::new("tgid", DataType::UInt32, false),
        Field::new("process_name", DataType::Utf8, true),
        Field::new("stack_id", DataType::Int32, true),
        Field::new("kernel_stack_id", DataType::Int32, true),
        Field::new("stack_kind", DataType::Utf8, true),
        Field::new("stack_frames", DataType::Utf8, true),
        Field::new("stack_trace", DataType::Utf8, true),
        Field::new("cpu", DataType::UInt8, false),
        // SchedSwitch fields (nullable)
        Field::new("prev_pid", DataType::UInt32, true),
        Field::new("next_pid", DataType::UInt32, true),
        Field::new("prev_state", DataType::Int64, true),
        // ProcessFork fields (nullable)
        Field::new("parent_pid", DataType::UInt32, true),
        Field::new("child_pid", DataType::UInt32, true),
        // ProcessExit fields (nullable)
        Field::new("exit_code", DataType::Int32, true),
        // PageFault fields (nullable)
        Field::new("address", DataType::UInt64, true),
        Field::new("error_code", DataType::UInt64, true),
        // Syscall fields (nullable)
        Field::new("fd", DataType::Int64, true),
        Field::new("count", DataType::UInt64, true),
        Field::new("ret", DataType::Int64, true),
        // io_uring completion fields (nullable)
        Field::new("submit_ts_ns", DataType::UInt64, true),
        Field::new("io_uring_opcode", DataType::UInt8, true),
        Field::new("io_uring_res", DataType::Int32, true),
    ])
}

/// Creates the final Arrow schema for persisted traces.
pub fn create_final_schema() -> Schema {
    Schema::new(vec![
        Field::new("event_type", DataType::Utf8, false),
        Field::new("ts_ns", DataType::UInt64, false),
        Field::new("pid", DataType::UInt32, false),
        Field::new("tgid", DataType::UInt32, false),
        Field::new("process_name", DataType::Utf8, true),
        Field::new("stack_id", DataType::Int32, true),
        Field::new("kernel_stack_id", DataType::Int32, true),
        Field::new("stack_kind", DataType::Utf8, true),
        Field::new(
            "stack_trace",
            DataType::List(Arc::new(Field::new("item", DataType::Utf8View, true))),
            true,
        ),
        Field::new("cpu", DataType::UInt8, false),
        // SchedSwitch fields (nullable)
        Field::new("prev_pid", DataType::UInt32, true),
        Field::new("next_pid", DataType::UInt32, true),
        Field::new("prev_state", DataType::Int64, true),
        // ProcessFork fields (nullable)
        Field::new("parent_pid", DataType::UInt32, true),
        Field::new("child_pid", DataType::UInt32, true),
        // ProcessExit fields (nullable)
        Field::new("exit_code", DataType::Int32, true),
        // PageFault fields (nullable)
        Field::new("address", DataType::UInt64, true),
        Field::new("error_code", DataType::UInt64, true),
        // Syscall fields (nullable)
        Field::new("fd", DataType::Int64, true),
        Field::new("count", DataType::UInt64, true),
        Field::new("ret", DataType::Int64, true),
        // io_uring completion fields (nullable)
        Field::new("submit_ts_ns", DataType::UInt64, true),
        Field::new("io_uring_opcode", DataType::UInt8, true),
        Field::new("io_uring_res", DataType::Int32, true),
    ])
}
