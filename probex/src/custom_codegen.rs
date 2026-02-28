use anyhow::{Context as _, Result, anyhow};
use probex_common::{
    EventHeader,
    viewer_api::{
        CustomPayloadFieldSchema, CustomPayloadSchema, CustomPayloadTypeKind, CustomProbeFieldRef,
        CustomProbeFilterOp, CustomProbeSpec, ProbeSchema, ProbeSchemaKind,
    },
};
use std::{
    collections::{HashMap, HashSet},
    ffi::{CString, OsString},
    fs,
    fs::OpenOptions,
    hash::{Hash, Hasher},
    io::ErrorKind,
    os::unix::{ffi::OsStrExt, process::CommandExt},
    path::{Path, PathBuf},
    process::Command,
    time::{Duration, Instant, SystemTime},
};

const MAX_CUSTOM_VALUES: usize = 8;
const EMBEDDED_EBPF_CARGO_TOML: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../probex-ebpf/Cargo.toml"
));
const EMBEDDED_EBPF_BUILD_RS: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../probex-ebpf/build.rs"
));
const EMBEDDED_EBPF_LIB_RS: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../probex-ebpf/src/lib.rs"
));
const EMBEDDED_EBPF_MAIN_RS: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../probex-ebpf/src/main.rs"
));

#[derive(Clone, Debug)]
pub(crate) enum CompiledCustomProbeKind {
    Tracepoint,
    Fentry,
    Fexit,
}

#[derive(Clone, Debug)]
enum CompiledFieldSource {
    TracepointOffset(u32),
    FunctionArg(usize),
    FunctionReturn(usize),
}

#[derive(Clone, Debug)]
pub(crate) struct CompiledCustomFilter {
    pub(crate) field_name: String,
    pub(crate) signed: bool,
    pub(crate) op: CustomProbeFilterOp,
    pub(crate) value: Option<String>,
}

#[derive(Clone, Debug)]
pub(crate) struct CompiledCustomField {
    pub(crate) field_id: u16,
    pub(crate) name: String,
    pub(crate) key: String,
    pub(crate) size: u32,
    pub(crate) signed: bool,
    source: CompiledFieldSource,
}

#[derive(Clone, Debug)]
pub(crate) struct CompiledCustomProbe {
    pub(crate) probe_id: u32,
    pub(crate) probe_display_name: String,
    pub(crate) custom_event_type: String,
    pub(crate) category: String,
    pub(crate) probe_name: String,
    pub(crate) kind: CompiledCustomProbeKind,
    pub(crate) program_name: String,
    pub(crate) record_stack_trace: bool,
    pub(crate) recorded_fields: Vec<CompiledCustomField>,
    pub(crate) read_fields: Vec<CompiledCustomField>,
    pub(crate) filters: Vec<CompiledCustomFilter>,
}

#[derive(Default)]
pub(crate) struct CompiledCustomPlan {
    pub(crate) by_probe_id: HashMap<u32, CompiledCustomProbe>,
    pub(crate) payload_schemas: Vec<CustomPayloadSchema>,
}

impl CompiledCustomPlan {
    pub(crate) fn payload_schemas_json(&self) -> Result<String> {
        serde_json::to_string(&self.payload_schemas)
            .with_context(|| "failed to encode custom payload schemas as json")
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub(crate) struct CustomProbeRuntimeValue {
    pub(crate) field_id: u16,
    pub(crate) _padding: u16,
    pub(crate) value: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub(crate) struct CustomProbeRuntimeEvent {
    pub(crate) header: EventHeader,
    pub(crate) probe_id: u32,
    pub(crate) value_count: u16,
    pub(crate) _padding: u16,
    pub(crate) values: [CustomProbeRuntimeValue; MAX_CUSTOM_VALUES],
}

fn field_ref_key(field_ref: &CustomProbeFieldRef) -> String {
    match field_ref {
        CustomProbeFieldRef::Field { name } => format!("field:{name}"),
        CustomProbeFieldRef::Arg { name } => format!("arg:{name}"),
        CustomProbeFieldRef::Return => "ret".to_string(),
    }
}

fn field_ref_display_name(field_ref: &CustomProbeFieldRef) -> String {
    match field_ref {
        CustomProbeFieldRef::Field { name } => name.clone(),
        CustomProbeFieldRef::Arg { name } => name.clone(),
        CustomProbeFieldRef::Return => "ret".to_string(),
    }
}

fn normalize_scalar_type_tokens(field_type: &str) -> String {
    field_type
        .split_whitespace()
        .filter(|token| {
            !matches!(
                *token,
                "const" | "volatile" | "restrict" | "__user" | "__rcu" | "__iomem"
            )
        })
        .collect::<Vec<_>>()
        .join(" ")
        .to_ascii_lowercase()
}

fn scalar_layout_from_type(field_type: &str) -> Result<(u32, bool)> {
    let normalized = normalize_scalar_type_tokens(field_type);
    let layout = match normalized.as_str() {
        "u8" | "__u8" | "unsigned char" | "bool" | "_bool" | "char" => (1, false),
        "i8" | "__s8" | "signed char" => (1, true),
        "u16" | "__u16" | "unsigned short" | "unsigned short int" => (2, false),
        "i16" | "__s16" | "short" | "short int" | "signed short" | "signed short int" => (2, true),
        "u32" | "__u32" | "unsigned" | "unsigned int" => (4, false),
        "i32" | "__s32" | "int" | "signed" | "signed int" => (4, true),
        "u64"
        | "__u64"
        | "unsigned long"
        | "unsigned long int"
        | "unsigned long long"
        | "unsigned long long int" => (8, false),
        "i64"
        | "__s64"
        | "long"
        | "long int"
        | "signed long"
        | "signed long int"
        | "long long"
        | "long long int"
        | "signed long long"
        | "signed long long int" => (8, true),
        _ => {
            return Err(anyhow!(
                "unsupported scalar type '{}' for runtime custom probes",
                field_type
            ));
        }
    };
    Ok(layout)
}

fn read_type_for_field(field: &CompiledCustomField) -> Result<&'static str> {
    match (field.size, field.signed) {
        (1, true) => Ok("i8"),
        (1, false) => Ok("u8"),
        (2, true) => Ok("i16"),
        (2, false) => Ok("u16"),
        (4, true) => Ok("i32"),
        (4, false) => Ok("u32"),
        (8, true) => Ok("i64"),
        (8, false) => Ok("u64"),
        _ => Err(anyhow!(
            "field '{}' has unsupported size/sign combination (size={}, signed={})",
            field.name,
            field.size,
            field.signed
        )),
    }
}

fn compiled_field_read_expr(field: &CompiledCustomField, rust_ty: &str) -> String {
    match field.source {
        CompiledFieldSource::TracepointOffset(offset) => {
            format!("unsafe {{ ctx.read_at::<{rust_ty}>({offset}usize)? }}")
        }
        CompiledFieldSource::FunctionArg(index) => {
            format!("unsafe {{ ctx.arg::<{rust_ty}>({index}usize) }}")
        }
        CompiledFieldSource::FunctionReturn(index) => {
            format!("unsafe {{ ctx.arg::<{rust_ty}>({index}usize) }}")
        }
    }
}

fn sanitize_ident(name: &str) -> String {
    let mut out = String::with_capacity(name.len() + 8);
    for ch in name.chars() {
        if ch.is_ascii_alphanumeric() || ch == '_' {
            out.push(ch);
        } else {
            out.push('_');
        }
    }
    if out.is_empty() || out.as_bytes()[0].is_ascii_digit() {
        out.insert(0, '_');
    }
    out
}

fn parse_u64_filter_literal(input: &str) -> Result<u64> {
    if let Some(hex) = input
        .strip_prefix("0x")
        .or_else(|| input.strip_prefix("0X"))
    {
        return u64::from_str_radix(hex, 16)
            .with_context(|| format!("invalid hexadecimal integer literal '{input}'"));
    }
    input
        .parse::<u64>()
        .with_context(|| format!("invalid unsigned integer literal '{input}'"))
}

fn parse_i64_filter_literal(input: &str) -> Result<i64> {
    if let Some(rest) = input.strip_prefix('-')
        && let Some(hex) = rest.strip_prefix("0x").or_else(|| rest.strip_prefix("0X"))
    {
        let magnitude = i64::from_str_radix(hex, 16)
            .with_context(|| format!("invalid hexadecimal integer literal '{input}'"))?;
        return magnitude
            .checked_neg()
            .ok_or_else(|| anyhow!("signed integer literal overflows i64: '{input}'"));
    }
    if let Some(hex) = input
        .strip_prefix("0x")
        .or_else(|| input.strip_prefix("0X"))
    {
        return i64::from_str_radix(hex, 16)
            .with_context(|| format!("invalid hexadecimal integer literal '{input}'"));
    }
    input
        .parse::<i64>()
        .with_context(|| format!("invalid signed integer literal '{input}'"))
}

fn render_filter_expr(filter: &CompiledCustomFilter) -> Result<String> {
    let var = format!("field_{}", sanitize_ident(&filter.field_name));
    let lhs = if filter.signed {
        format!("{var} as i64")
    } else {
        format!("{var} as u64")
    };

    let expr = match filter.op {
        CustomProbeFilterOp::Eq => {
            let rhs = filter
                .value
                .as_deref()
                .ok_or_else(|| anyhow!("missing filter value"))?;
            if filter.signed {
                format!("{lhs} == {}i64", parse_i64_filter_literal(rhs)?)
            } else {
                format!("{lhs} == {}u64", parse_u64_filter_literal(rhs)?)
            }
        }
        CustomProbeFilterOp::Ne => {
            let rhs = filter
                .value
                .as_deref()
                .ok_or_else(|| anyhow!("missing filter value"))?;
            if filter.signed {
                format!("{lhs} != {}i64", parse_i64_filter_literal(rhs)?)
            } else {
                format!("{lhs} != {}u64", parse_u64_filter_literal(rhs)?)
            }
        }
        CustomProbeFilterOp::Gt => {
            let rhs = filter
                .value
                .as_deref()
                .ok_or_else(|| anyhow!("missing filter value"))?;
            if filter.signed {
                format!("{lhs} > {}i64", parse_i64_filter_literal(rhs)?)
            } else {
                format!("{lhs} > {}u64", parse_u64_filter_literal(rhs)?)
            }
        }
        CustomProbeFilterOp::Ge => {
            let rhs = filter
                .value
                .as_deref()
                .ok_or_else(|| anyhow!("missing filter value"))?;
            if filter.signed {
                format!("{lhs} >= {}i64", parse_i64_filter_literal(rhs)?)
            } else {
                format!("{lhs} >= {}u64", parse_u64_filter_literal(rhs)?)
            }
        }
        CustomProbeFilterOp::Lt => {
            let rhs = filter
                .value
                .as_deref()
                .ok_or_else(|| anyhow!("missing filter value"))?;
            if filter.signed {
                format!("{lhs} < {}i64", parse_i64_filter_literal(rhs)?)
            } else {
                format!("{lhs} < {}u64", parse_u64_filter_literal(rhs)?)
            }
        }
        CustomProbeFilterOp::Le => {
            let rhs = filter
                .value
                .as_deref()
                .ok_or_else(|| anyhow!("missing filter value"))?;
            if filter.signed {
                format!("{lhs} <= {}i64", parse_i64_filter_literal(rhs)?)
            } else {
                format!("{lhs} <= {}u64", parse_u64_filter_literal(rhs)?)
            }
        }
        CustomProbeFilterOp::IsNull => format!("{lhs} == 0"),
        CustomProbeFilterOp::IsNotNull => format!("{lhs} != 0"),
        CustomProbeFilterOp::Contains
        | CustomProbeFilterOp::StartsWith
        | CustomProbeFilterOp::EndsWith => {
            return Err(anyhow!(
                "string-like filters are not supported in generated eBPF"
            ));
        }
    };

    Ok(expr)
}

fn render_generated_custom_probe(probe: &CompiledCustomProbe) -> Result<String> {
    if probe.recorded_fields.len() > MAX_CUSTOM_VALUES {
        return Err(anyhow!(
            "probe '{}' records {} fields but max is {}",
            probe.probe_display_name,
            probe.recorded_fields.len(),
            MAX_CUSTOM_VALUES
        ));
    }

    let mut prelude = String::new();
    for field in &probe.read_fields {
        let read_ty = read_type_for_field(field)?;
        let var = format!("field_{}", sanitize_ident(&field.key));
        let read_expr = compiled_field_read_expr(field, read_ty);
        prelude.push_str(&format!("    let {var}: {read_ty} = {read_expr};\n"));
    }

    let mut filters = String::new();
    for filter in &probe.filters {
        let expr = render_filter_expr(filter)?;
        filters.push_str(&format!(
            "    if !({expr}) {{\n        return Ok(0);\n    }}\n"
        ));
    }

    let header_expr = if probe.record_stack_trace {
        "make_header(ctx, EventType::SchedSwitch)"
    } else {
        "make_header_without_stack(ctx, EventType::SchedSwitch)"
    };

    let mut value_assignments = String::new();
    for (idx, field) in probe.recorded_fields.iter().enumerate() {
        let var = format!("field_{}", sanitize_ident(&field.key));
        let encoded_value = if field.signed {
            format!("({var} as i64) as u64")
        } else {
            format!("{var} as u64")
        };
        value_assignments.push_str(&format!(
            "        (*event_ptr).values[{idx}] = GeneratedCustomValue {{ field_id: {}, _padding: 0, value: {encoded_value} }};\n",
            field.field_id
        ));
    }

    let (attr, context): (String, String) = match probe.kind {
        CompiledCustomProbeKind::Tracepoint => {
            ("#[tracepoint]".to_string(), "TracePointContext".to_string())
        }
        CompiledCustomProbeKind::Fentry => (
            format!("#[fentry(function = \"{}\")]", probe.probe_name),
            "FEntryContext".to_string(),
        ),
        CompiledCustomProbeKind::Fexit => (
            format!("#[fexit(function = \"{}\")]", probe.probe_name),
            "FExitContext".to_string(),
        ),
    };

    Ok(format!(
        r#"
{attr}
pub fn {program_name}(ctx: {context}) -> u32 {{
    match try_{program_name}(&ctx) {{
        Ok(ret) => ret,
        Err(_) => 1,
    }}
}}

fn try_{program_name}(ctx: &{context}) -> Result<u32, i64> {{
{prelude}    if !is_traced(ctx.tgid()) {{
        return Ok(0);
    }}
{filters}    if let Some(mut buf) = CUSTOM_EVENTS.reserve::<GeneratedCustomEvent>(0) {{
        let event_ptr = buf.as_mut_ptr();
        unsafe {{
            core::ptr::write_bytes(
                event_ptr as *mut u8,
                0,
                core::mem::size_of::<GeneratedCustomEvent>(),
            );
            (*event_ptr).header = {header_expr};
            (*event_ptr).header.event_type = 255;
            (*event_ptr).probe_id = {probe_id};
            (*event_ptr).value_count = {value_count};
            (*event_ptr)._padding = 0;
{value_assignments}
        }}
        buf.submit(BPF_RB_FORCE_WAKEUP as u64);
    }}

    Ok(0)
}}
"#,
        attr = attr,
        context = context,
        program_name = probe.program_name,
        prelude = prelude,
        filters = filters,
        header_expr = header_expr,
        value_assignments = value_assignments,
        probe_id = probe.probe_id,
        value_count = probe.recorded_fields.len(),
    ))
}

pub(crate) fn compile_custom_probe_plan(
    specs: &[CustomProbeSpec],
    resolved_schemas: &HashMap<String, ProbeSchema>,
) -> Result<CompiledCustomPlan> {
    let mut plan = CompiledCustomPlan::default();

    for (idx, spec) in specs.iter().enumerate() {
        let schema = resolved_schemas
            .get(&spec.probe_display_name)
            .ok_or_else(|| {
                anyhow!(
                    "custom probe[{}] '{}': schema is missing from resolved catalog data",
                    idx,
                    spec.probe_display_name
                )
            })?;
        let kind = match schema.kind {
            ProbeSchemaKind::Tracepoint => CompiledCustomProbeKind::Tracepoint,
            ProbeSchemaKind::Fentry => CompiledCustomProbeKind::Fentry,
            ProbeSchemaKind::Fexit => CompiledCustomProbeKind::Fexit,
        };
        if matches!(kind, CompiledCustomProbeKind::Tracepoint) && schema.fields.is_empty() {
            return Err(anyhow!(
                "custom probe[{}] '{}': resolved schema has no tracepoint fields",
                idx,
                spec.probe_display_name
            ));
        }

        let category = schema.target.clone();
        let probe_name = schema.probe.clone();

        let mut seen_record_names = HashSet::new();
        let mut recorded_fields = Vec::new();

        for record_ref in &spec.record_fields {
            let key = field_ref_key(record_ref);
            if !seen_record_names.insert(key.clone()) {
                continue;
            }
            let compiled_field = match (kind.clone(), record_ref) {
                (CompiledCustomProbeKind::Tracepoint, CustomProbeFieldRef::Field { name }) => {
                    let field =
                        schema
                            .fields
                            .iter()
                            .find(|f| &f.name == name)
                            .ok_or_else(|| {
                                anyhow!(
                                    "custom probe[{}] '{}': unknown field '{}'",
                                    idx,
                                    spec.probe_display_name,
                                    name
                                )
                            })?;
                    CompiledCustomField {
                        field_id: (recorded_fields.len() + 1) as u16,
                        name: field_ref_display_name(record_ref),
                        key,
                        size: field.size,
                        signed: field.is_signed,
                        source: CompiledFieldSource::TracepointOffset(field.offset),
                    }
                }
                (
                    CompiledCustomProbeKind::Fentry | CompiledCustomProbeKind::Fexit,
                    CustomProbeFieldRef::Arg { name },
                ) => {
                    let (arg_idx, arg) = schema
                        .args
                        .iter()
                        .enumerate()
                        .find(|(_, arg)| &arg.name == name)
                        .ok_or_else(|| {
                            anyhow!(
                                "custom probe[{}] '{}': unknown arg '{}'",
                                idx,
                                spec.probe_display_name,
                                name
                            )
                        })?;
                    let (size, signed) =
                        scalar_layout_from_type(&arg.arg_type).with_context(|| {
                            format!(
                                "custom probe[{}] '{}': unsupported arg type '{}' for '{}'",
                                idx, spec.probe_display_name, arg.arg_type, name
                            )
                        })?;
                    CompiledCustomField {
                        field_id: (recorded_fields.len() + 1) as u16,
                        name: field_ref_display_name(record_ref),
                        key,
                        size,
                        signed,
                        source: CompiledFieldSource::FunctionArg(arg_idx),
                    }
                }
                (CompiledCustomProbeKind::Fexit, CustomProbeFieldRef::Return) => {
                    let return_ty = schema.return_type.as_deref().ok_or_else(|| {
                        anyhow!(
                            "custom probe[{}] '{}': return type is missing",
                            idx,
                            spec.probe_display_name
                        )
                    })?;
                    let (size, signed) = scalar_layout_from_type(return_ty).with_context(|| {
                        format!(
                            "custom probe[{}] '{}': unsupported return type '{}'",
                            idx, spec.probe_display_name, return_ty
                        )
                    })?;
                    CompiledCustomField {
                        field_id: (recorded_fields.len() + 1) as u16,
                        name: field_ref_display_name(record_ref),
                        key,
                        size,
                        signed,
                        source: CompiledFieldSource::FunctionReturn(schema.args.len()),
                    }
                }
                (CompiledCustomProbeKind::Fentry, CustomProbeFieldRef::Return) => {
                    return Err(anyhow!(
                        "custom probe[{}] '{}': fentry probes cannot use return value",
                        idx,
                        spec.probe_display_name
                    ));
                }
                (CompiledCustomProbeKind::Tracepoint, CustomProbeFieldRef::Arg { name }) => {
                    return Err(anyhow!(
                        "custom probe[{}] '{}': tracepoint probes do not support arg '{}'",
                        idx,
                        spec.probe_display_name,
                        name
                    ));
                }
                (CompiledCustomProbeKind::Tracepoint, CustomProbeFieldRef::Return) => {
                    return Err(anyhow!(
                        "custom probe[{}] '{}': tracepoint probes do not support return value",
                        idx,
                        spec.probe_display_name
                    ));
                }
                (
                    CompiledCustomProbeKind::Fentry | CompiledCustomProbeKind::Fexit,
                    CustomProbeFieldRef::Field { name },
                ) => {
                    return Err(anyhow!(
                        "custom probe[{}] '{}': function probes do not support tracepoint field '{}'",
                        idx,
                        spec.probe_display_name,
                        name
                    ));
                }
            };
            recorded_fields.push(compiled_field);
        }

        if recorded_fields.len() > MAX_CUSTOM_VALUES {
            return Err(anyhow!(
                "custom probe[{}] '{}': records {} fields, max supported is {}",
                idx,
                spec.probe_display_name,
                recorded_fields.len(),
                MAX_CUSTOM_VALUES
            ));
        }

        let mut read_fields = recorded_fields.clone();
        let mut read_field_names = read_fields
            .iter()
            .map(|field| field.key.clone())
            .collect::<HashSet<_>>();

        let mut filters = Vec::new();
        for filter in &spec.filters {
            let key = field_ref_key(&filter.field);
            let parsed_filter_field = match (kind.clone(), &filter.field) {
                (CompiledCustomProbeKind::Tracepoint, CustomProbeFieldRef::Field { name }) => {
                    let field =
                        schema
                            .fields
                            .iter()
                            .find(|f| &f.name == name)
                            .ok_or_else(|| {
                                anyhow!(
                                    "custom probe[{}] '{}': unknown filter field '{}'",
                                    idx,
                                    spec.probe_display_name,
                                    name
                                )
                            })?;
                    CompiledCustomField {
                        field_id: 0,
                        name: field_ref_display_name(&filter.field),
                        key: key.clone(),
                        size: field.size,
                        signed: field.is_signed,
                        source: CompiledFieldSource::TracepointOffset(field.offset),
                    }
                }
                (
                    CompiledCustomProbeKind::Fentry | CompiledCustomProbeKind::Fexit,
                    CustomProbeFieldRef::Arg { name },
                ) => {
                    let (arg_idx, arg) = schema
                        .args
                        .iter()
                        .enumerate()
                        .find(|(_, arg)| &arg.name == name)
                        .ok_or_else(|| {
                            anyhow!(
                                "custom probe[{}] '{}': unknown filter arg '{}'",
                                idx,
                                spec.probe_display_name,
                                name
                            )
                        })?;
                    let (size, signed) =
                        scalar_layout_from_type(&arg.arg_type).with_context(|| {
                            format!(
                                "custom probe[{}] '{}': unsupported arg type '{}' for '{}'",
                                idx, spec.probe_display_name, arg.arg_type, name
                            )
                        })?;
                    CompiledCustomField {
                        field_id: 0,
                        name: field_ref_display_name(&filter.field),
                        key: key.clone(),
                        size,
                        signed,
                        source: CompiledFieldSource::FunctionArg(arg_idx),
                    }
                }
                (CompiledCustomProbeKind::Fexit, CustomProbeFieldRef::Return) => {
                    let return_ty = schema.return_type.as_deref().ok_or_else(|| {
                        anyhow!(
                            "custom probe[{}] '{}': return type is missing",
                            idx,
                            spec.probe_display_name
                        )
                    })?;
                    let (size, signed) = scalar_layout_from_type(return_ty).with_context(|| {
                        format!(
                            "custom probe[{}] '{}': unsupported return type '{}'",
                            idx, spec.probe_display_name, return_ty
                        )
                    })?;
                    CompiledCustomField {
                        field_id: 0,
                        name: field_ref_display_name(&filter.field),
                        key: key.clone(),
                        size,
                        signed,
                        source: CompiledFieldSource::FunctionReturn(schema.args.len()),
                    }
                }
                (CompiledCustomProbeKind::Fentry, CustomProbeFieldRef::Return) => {
                    return Err(anyhow!(
                        "custom probe[{}] '{}': fentry probes cannot filter on return value",
                        idx,
                        spec.probe_display_name
                    ));
                }
                (CompiledCustomProbeKind::Tracepoint, CustomProbeFieldRef::Arg { name }) => {
                    return Err(anyhow!(
                        "custom probe[{}] '{}': tracepoint probes do not support filter arg '{}'",
                        idx,
                        spec.probe_display_name,
                        name
                    ));
                }
                (CompiledCustomProbeKind::Tracepoint, CustomProbeFieldRef::Return) => {
                    return Err(anyhow!(
                        "custom probe[{}] '{}': tracepoint probes do not support return filter",
                        idx,
                        spec.probe_display_name
                    ));
                }
                (
                    CompiledCustomProbeKind::Fentry | CompiledCustomProbeKind::Fexit,
                    CustomProbeFieldRef::Field { name },
                ) => {
                    return Err(anyhow!(
                        "custom probe[{}] '{}': function probes do not support tracepoint filter field '{}'",
                        idx,
                        spec.probe_display_name,
                        name
                    ));
                }
            };
            if !read_field_names.contains(&key) {
                read_fields.push(parsed_filter_field.clone());
                read_field_names.insert(key.clone());
            }
            filters.push(CompiledCustomFilter {
                field_name: key,
                signed: parsed_filter_field.signed,
                op: filter.op.clone(),
                value: filter.value.clone(),
            });
        }

        let probe_id = (idx + 1) as u32;
        let custom_event_type = format!("custom:{probe_name}");
        let compiled = CompiledCustomProbe {
            probe_id,
            probe_display_name: spec.probe_display_name.clone(),
            custom_event_type: custom_event_type.clone(),
            category,
            probe_name,
            kind,
            program_name: format!("custom_probe_{idx}"),
            record_stack_trace: spec.record_stack_trace,
            recorded_fields: recorded_fields.clone(),
            read_fields,
            filters,
        };

        plan.payload_schemas.push(CustomPayloadSchema {
            schema_id: probe_id,
            probe_display_name: spec.probe_display_name.clone(),
            event_type: custom_event_type,
            fields: recorded_fields
                .iter()
                .map(|field| CustomPayloadFieldSchema {
                    field_id: field.field_id,
                    name: field.name.clone(),
                    type_kind: if field.signed {
                        CustomPayloadTypeKind::I64
                    } else {
                        CustomPayloadTypeKind::U64
                    },
                })
                .collect(),
        });

        plan.by_probe_id.insert(compiled.probe_id, compiled);
    }

    Ok(plan)
}

pub(crate) fn generate_custom_probe_source(plan: &CompiledCustomPlan) -> Result<String> {
    let mut source = String::new();
    source.push_str(
        r#"
const MAX_CUSTOM_VALUES: usize = 8;

#[repr(C)]
#[derive(Clone, Copy)]
struct GeneratedCustomValue {
    field_id: u16,
    _padding: u16,
    value: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct GeneratedCustomEvent {
    header: EventHeader,
    probe_id: u32,
    value_count: u16,
    _padding: u16,
    values: [GeneratedCustomValue; MAX_CUSTOM_VALUES],
}

#[map]
static CUSTOM_EVENTS: RingBuf = RingBuf::with_byte_size(4 * 1024 * 1024, 0);
"#,
    );

    let mut probes = plan.by_probe_id.values().cloned().collect::<Vec<_>>();
    probes.sort_by_key(|probe| probe.probe_id);
    for probe in probes {
        source.push_str(&render_generated_custom_probe(&probe)?);
    }

    Ok(source)
}

pub(crate) fn generate_custom_probe_source_preview(
    specs: &[CustomProbeSpec],
    resolved_schemas: &HashMap<String, ProbeSchema>,
) -> Result<String> {
    let plan = compile_custom_probe_plan(specs, resolved_schemas)
        .with_context(|| "step=compile_custom_probe_plan failed")?;
    generate_custom_probe_source(&plan).with_context(|| "step=generate_rust_code failed")
}

fn bpf_target_triple_runtime() -> String {
    let prefix = if cfg!(target_endian = "big") {
        "bpfeb"
    } else {
        "bpfel"
    };
    format!("{prefix}-unknown-none")
}

fn bpf_target_arch_runtime() -> String {
    let arch = std::env::consts::ARCH;
    if arch.starts_with("riscv64") {
        "riscv64".to_string()
    } else {
        arch.to_string()
    }
}

fn parse_env_u32(name: &str) -> Result<Option<u32>> {
    let raw = match std::env::var(name) {
        Ok(value) => value,
        Err(std::env::VarError::NotPresent) => return Ok(None),
        Err(error) => return Err(anyhow!("failed to read env {name}: {error}")),
    };
    let value = raw
        .parse::<u32>()
        .with_context(|| format!("invalid {name}='{raw}'"))?;
    Ok(Some(value))
}

fn generated_builds_root() -> PathBuf {
    if let Ok(path) = std::env::var("PROBEX_GENERATED_ROOT")
        && !path.trim().is_empty()
    {
        return PathBuf::from(path);
    }
    if let Ok(path) = std::env::var("XDG_CACHE_HOME")
        && !path.trim().is_empty()
    {
        return PathBuf::from(path).join("probex").join("generated");
    }
    if let Ok(path) = std::env::var("HOME")
        && !path.trim().is_empty()
    {
        return PathBuf::from(path)
            .join(".cache")
            .join("probex")
            .join("generated");
    }
    std::env::temp_dir().join("probex-generated")
}

fn resolve_cargo_drop_target() -> Result<Option<(u32, u32)>> {
    let euid = unsafe { libc::geteuid() };
    if euid != 0 {
        return Ok(None);
    }

    let uid = parse_env_u32("SUDO_UID")?;
    let gid = parse_env_u32("SUDO_GID")?;
    match (uid, gid) {
        (Some(uid), Some(gid)) if uid > 0 && gid > 0 => Ok(Some((uid, gid))),
        (None, None) => Ok(None),
        _ => Err(anyhow!(
            "running as root requires both SUDO_UID and SUDO_GID to drop privileges for generated ebpf build"
        )),
    }
}

fn chown_path(path: &Path, uid: u32, gid: u32) -> Result<()> {
    let bytes = path.as_os_str().as_bytes();
    let c_path = CString::new(bytes)
        .with_context(|| format!("path contains interior NUL: '{}'", path.display()))?;
    let ret = unsafe { libc::chown(c_path.as_ptr(), uid, gid) };
    if ret != 0 {
        return Err(anyhow!(
            "failed to chown '{}' to uid={}, gid={}: {}",
            path.display(),
            uid,
            gid,
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

fn write_embedded_ebpf_scaffold(scaffold_root: &Path, probex_common_root: &Path) -> Result<()> {
    fs::create_dir_all(scaffold_root.join("src")).with_context(|| {
        format!(
            "failed to create embedded scaffold src dir '{}'",
            scaffold_root.join("src").display()
        )
    })?;

    let probex_common_path = probex_common_root
        .to_str()
        .ok_or_else(|| anyhow!("probex-common path is not valid UTF-8"))?;
    let mut cargo_toml = EMBEDDED_EBPF_CARGO_TOML.to_string();
    let old_dep = "path = \"../probex-common\"";
    let new_dep = format!("path = \"{}\"", probex_common_path.replace('\\', "\\\\"));
    let replacements = [
        ("edition.workspace = true", "edition = \"2024\""),
        (
            "license.workspace = true",
            "license = \"MIT OR Apache-2.0\"",
        ),
        (
            "repository.workspace = true",
            "repository = \"https://github.com/XiangpengHao/probex\"",
        ),
        (
            "homepage.workspace = true",
            "homepage = \"https://github.com/XiangpengHao/probex\"",
        ),
        (
            "aya-ebpf = { workspace = true }",
            "aya-ebpf = { version = \"0.1.1\", default-features = false }",
        ),
        (
            "aya-log-ebpf = { workspace = true }",
            "aya-log-ebpf = { version = \"0.1.0\", default-features = false }",
        ),
        (
            "which = { workspace = true }",
            "which = { version = \"6.0.0\", default-features = false }",
        ),
    ];

    if !cargo_toml.contains(old_dep) {
        return Err(anyhow!(
            "embedded probex-ebpf Cargo.toml missing expected dependency marker '{}'",
            old_dep
        ));
    }
    cargo_toml = cargo_toml.replace(old_dep, &new_dep);
    for (from, to) in replacements {
        if !cargo_toml.contains(from) {
            return Err(anyhow!(
                "embedded probex-ebpf Cargo.toml missing expected marker '{}'",
                from
            ));
        }
        cargo_toml = cargo_toml.replace(from, to);
    }

    fs::write(scaffold_root.join("Cargo.toml"), cargo_toml).with_context(|| {
        format!(
            "failed to write embedded scaffold file '{}'",
            scaffold_root.join("Cargo.toml").display()
        )
    })?;
    fs::write(scaffold_root.join("build.rs"), EMBEDDED_EBPF_BUILD_RS).with_context(|| {
        format!(
            "failed to write embedded scaffold file '{}'",
            scaffold_root.join("build.rs").display()
        )
    })?;
    fs::write(
        scaffold_root.join("src").join("lib.rs"),
        EMBEDDED_EBPF_LIB_RS,
    )
    .with_context(|| {
        format!(
            "failed to write embedded scaffold file '{}'",
            scaffold_root.join("src").join("lib.rs").display()
        )
    })?;
    fs::write(
        scaffold_root.join("src").join("main.rs"),
        EMBEDDED_EBPF_MAIN_RS,
    )
    .with_context(|| {
        format!(
            "failed to write embedded scaffold file '{}'",
            scaffold_root.join("src").join("main.rs").display()
        )
    })?;

    Ok(())
}

struct BuildLockGuard {
    path: PathBuf,
    _file: fs::File,
}

impl Drop for BuildLockGuard {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

pub(crate) fn build_generated_ebpf_binary_path(source: &str) -> Result<PathBuf> {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    source.hash(&mut hasher);
    // Cache key must include scaffold contents so template/runtime edits invalidate
    // previously built generated binaries.
    EMBEDDED_EBPF_CARGO_TOML.hash(&mut hasher);
    EMBEDDED_EBPF_BUILD_RS.hash(&mut hasher);
    EMBEDDED_EBPF_LIB_RS.hash(&mut hasher);
    EMBEDDED_EBPF_MAIN_RS.hash(&mut hasher);
    let key = hasher.finish();

    let build_root = generated_builds_root().join(format!("{key:016x}"));
    let target = bpf_target_triple_runtime();
    let built_binary = build_root
        .join("target")
        .join(&target)
        .join("release")
        .join("probex");
    if built_binary.is_file() {
        return Ok(built_binary);
    }

    fs::create_dir_all(&build_root).with_context(|| {
        format!(
            "failed to create generated build directory '{}'",
            build_root.display()
        )
    })?;

    let lock_path = build_root.join(".build.lock");
    let lock_wait_timeout = Duration::from_secs(300);
    let lock_stale_after = Duration::from_secs(600);
    let wait_start = Instant::now();
    let lock_file = loop {
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&lock_path)
        {
            Ok(file) => break file,
            Err(error) if error.kind() == ErrorKind::AlreadyExists => {
                if built_binary.is_file() {
                    return Ok(built_binary);
                }
                if let Ok(metadata) = fs::metadata(&lock_path)
                    && let Ok(modified_at) = metadata.modified()
                {
                    let is_stale = SystemTime::now()
                        .duration_since(modified_at)
                        .map(|age| age > lock_stale_after)
                        .unwrap_or(false);
                    if is_stale {
                        let _ = fs::remove_file(&lock_path);
                        continue;
                    }
                }
                if wait_start.elapsed() > lock_wait_timeout {
                    return Err(anyhow!(
                        "timed out waiting for generated ebpf build lock '{}'",
                        lock_path.display()
                    ));
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(error) => {
                return Err(anyhow!(
                    "failed to create generated ebpf build lock '{}': {}",
                    lock_path.display(),
                    error
                ));
            }
        }
    };
    let _lock_guard = BuildLockGuard {
        path: lock_path,
        _file: lock_file,
    };

    if built_binary.is_file() {
        return Ok(built_binary);
    }

    let drop_target = resolve_cargo_drop_target()?;
    let generated_path = build_root.join("generated_probes.rs");
    fs::write(&generated_path, source).with_context(|| {
        format!(
            "failed to write generated probes source '{}'",
            generated_path.display()
        )
    })?;

    let probex_manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let workspace_root = probex_manifest_dir
        .parent()
        .ok_or_else(|| anyhow!("failed to resolve workspace root"))?;
    let probex_common_root = workspace_root.join("probex-common");
    let ebpf_root = build_root.join("probex-ebpf");
    write_embedded_ebpf_scaffold(&ebpf_root, &probex_common_root)?;

    let target_dir = build_root.join("target");
    fs::create_dir_all(&target_dir).with_context(|| {
        format!(
            "failed to create generated target directory '{}'",
            target_dir.display()
        )
    })?;
    let arch = bpf_target_arch_runtime();
    let mut rustflags = OsString::from("--cfg=bpf_target_arch=\"");
    rustflags.push(&arch);
    rustflags.push("\"\x1f-Cdebuginfo=2\x1f-Clink-arg=--btf\x1f--cfg=probex_generated_probes");

    let cargo_bin = std::env::var_os("CARGO").unwrap_or_else(|| OsString::from("cargo"));
    let mut cmd = Command::new(&cargo_bin);
    if let Some((uid, gid)) = drop_target {
        chown_path(&build_root, uid, gid)?;
        chown_path(&ebpf_root, uid, gid)?;
        chown_path(&generated_path, uid, gid)?;
        chown_path(&target_dir, uid, gid)?;
        cmd.uid(uid).gid(gid);
    }
    cmd.current_dir(&ebpf_root)
        .env("CARGO_ENCODED_RUSTFLAGS", rustflags)
        .env("PROBEX_GENERATED_PROBES_RS", &generated_path)
        .args([
            "build",
            "--package",
            "probex-ebpf",
            "-Z",
            "build-std=core",
            "--bins",
            "--release",
            "--target",
            target.as_str(),
            "--target-dir",
        ])
        .arg(&target_dir);
    let output = cmd
        .output()
        .with_context(|| format!("failed to run generated ebpf build command: {cmd:?}"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr_trimmed = stderr.trim();
        let stdout_trimmed = stdout.trim();
        let stderr_tail = if stderr_trimmed.len() > 12000 {
            &stderr_trimmed[stderr_trimmed.len() - 12000..]
        } else {
            stderr_trimmed
        };
        let stdout_tail = if stdout_trimmed.len() > 4000 {
            &stdout_trimmed[stdout_trimmed.len() - 4000..]
        } else {
            stdout_trimmed
        };

        let mut message = format!(
            "generated ebpf build failed with status: {}\ncommand: {:?}",
            output.status, cmd
        );
        if !stderr_tail.is_empty() {
            message.push_str("\n\nstderr:\n");
            message.push_str(stderr_tail);
        }
        if !stdout_tail.is_empty() {
            message.push_str("\n\nstdout:\n");
            message.push_str(stdout_tail);
        }
        return Err(anyhow!(message));
    }

    if !built_binary.is_file() {
        return Err(anyhow!(
            "generated ebpf build succeeded but output '{}' was not found",
            built_binary.display()
        ));
    }
    Ok(built_binary)
}

pub(crate) fn build_generated_ebpf_binary(source: &str) -> Result<Vec<u8>> {
    let path = build_generated_ebpf_binary_path(source)?;
    fs::read(&path)
        .with_context(|| format!("failed to read generated ebpf binary '{}'", path.display()))
}
