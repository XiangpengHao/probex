use crate::tracepoint_format;
use btf_rs::{Btf, BtfType, Type};
use nucleo_matcher::{
    Config, Matcher, Utf32String,
    pattern::{CaseMatching, Normalization, Pattern},
};
use probex_common::viewer_api::{
    ProbeSchema, ProbeSchemaArg, ProbeSchemaField, ProbeSchemaKind, ProbeSchemaSource,
    ProbeSchemasPageResponse, ProbeSchemasResponse,
};
use std::collections::HashMap;
use std::error::Error;
use std::fs;
use std::io::{Error as IoError, ErrorKind};
use std::path::Path;
use std::sync::{
    Arc, Mutex, OnceLock,
    atomic::{AtomicBool, Ordering},
};

pub type ProbeCatalogResult<T> = Result<T, Box<dyn Error + Send + Sync>>;

static PROBE_INDEX: OnceLock<Arc<ProbeIndexState>> = OnceLock::new();
static TRACEPOINT_FIELD_CACHE: OnceLock<Mutex<HashMap<String, Vec<ProbeSchemaField>>>> =
    OnceLock::new();

#[derive(Debug, Default)]
struct ProbeIndexState {
    started: AtomicBool,
    ready: AtomicBool,
    entries: Mutex<Vec<ProbeIndexEntry>>,
    error: Mutex<Option<String>>,
}

#[derive(Clone, Debug)]
struct ProbeIndexEntry {
    schema: ProbeSchema,
    search_text: Utf32String,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct FunctionCandidate {
    symbol: String,
    category: String,
}

#[derive(Clone, Debug, Default)]
struct FunctionSignature {
    return_type: Option<String>,
    args: Vec<ProbeSchemaArg>,
}

fn supported_integer_type_reason(field_type: &str) -> Option<String> {
    let normalized = field_type
        .split_whitespace()
        .filter(|token| {
            !matches!(
                *token,
                "const" | "volatile" | "restrict" | "__user" | "__rcu" | "__iomem"
            )
        })
        .collect::<Vec<_>>()
        .join(" ")
        .to_ascii_lowercase();
    let supported = matches!(
        normalized.as_str(),
        "u8" | "u16"
            | "u32"
            | "u64"
            | "i8"
            | "i16"
            | "i32"
            | "i64"
            | "__u8"
            | "__u16"
            | "__u32"
            | "__u64"
            | "__s8"
            | "__s16"
            | "__s32"
            | "__s64"
            | "bool"
            | "_bool"
            | "char"
            | "signed char"
            | "unsigned char"
            | "short"
            | "short int"
            | "signed short"
            | "signed short int"
            | "unsigned short"
            | "unsigned short int"
            | "int"
            | "signed"
            | "signed int"
            | "unsigned"
            | "unsigned int"
            | "long"
            | "long int"
            | "signed long"
            | "signed long int"
            | "unsigned long"
            | "unsigned long int"
            | "long long"
            | "long long int"
            | "signed long long"
            | "signed long long int"
            | "unsigned long long"
            | "unsigned long long int"
    );
    if supported {
        None
    } else {
        Some(format!(
            "unsupported type '{}'; only integer/bool scalar types are supported",
            field_type
        ))
    }
}

#[derive(Clone, Debug)]
pub struct ProbeSchemasQuery {
    pub search: Option<String>,
    pub category: Option<String>,
    pub provider: Option<String>,
    pub kinds: Option<Vec<ProbeSchemaKind>>,
    pub source: Option<ProbeSchemaSource>,
    pub offset: usize,
    pub limit: usize,
    pub include_fields: bool,
}

fn discover_tracepoints(events_root: &Path) -> ProbeCatalogResult<Vec<(String, String)>> {
    let mut discovered = Vec::new();
    for category_entry in fs::read_dir(events_root)? {
        let category_entry = category_entry?;
        if !category_entry.file_type()?.is_dir() {
            continue;
        }
        let category_name = category_entry.file_name().to_string_lossy().to_string();

        for probe_entry in fs::read_dir(category_entry.path())? {
            let probe_entry = probe_entry?;
            if !probe_entry.file_type()?.is_dir() {
                continue;
            }
            let probe_name = probe_entry.file_name().to_string_lossy().to_string();
            let format_path =
                tracepoint_format::tracepoint_format_path(events_root, &category_name, &probe_name);
            if format_path.is_file() {
                discovered.push((category_name.clone(), probe_name));
            }
        }
    }
    discovered.sort_unstable();
    if discovered.is_empty() {
        return Err(IoError::new(
            ErrorKind::NotFound,
            format!("no tracepoints discovered under {}", events_root.display()),
        )
        .into());
    }

    Ok(discovered)
}

fn infer_symbol_category(symbol: &str) -> String {
    let trimmed = symbol.trim_start_matches('_');
    let head = trimmed.split('_').next().unwrap_or_default();
    if head.is_empty() {
        "kernel".to_string()
    } else {
        head.to_string()
    }
}

fn parse_available_filter_functions() -> ProbeCatalogResult<Vec<FunctionCandidate>> {
    const CANDIDATES: &[&str] = &[
        "/sys/kernel/tracing/available_filter_functions",
        "/sys/kernel/debug/tracing/available_filter_functions",
    ];

    let mut last_err: Option<IoError> = None;
    for candidate in CANDIDATES {
        let content = match fs::read_to_string(candidate) {
            Ok(content) => content,
            Err(error) => {
                last_err = Some(IoError::new(
                    ErrorKind::NotFound,
                    format!("failed to read {}: {}", candidate, error),
                ));
                continue;
            }
        };

        let mut symbols = content
            .lines()
            .filter_map(|line| {
                let mut parts = line.split_whitespace();
                let symbol = parts.next()?.trim();
                if symbol.is_empty() {
                    return None;
                }

                let module_or_kernel = parts
                    .find_map(|token| {
                        let stripped = token
                            .strip_prefix('[')
                            .and_then(|v| v.strip_suffix(']'))
                            .unwrap_or("");
                        (!stripped.is_empty()).then(|| stripped.to_string())
                    })
                    .unwrap_or_else(|| "kernel".to_string());
                let category = if module_or_kernel == "kernel" {
                    infer_symbol_category(symbol)
                } else {
                    module_or_kernel
                };
                Some(FunctionCandidate {
                    symbol: symbol.to_string(),
                    category,
                })
            })
            .collect::<Vec<_>>();
        symbols.sort_unstable();
        symbols.dedup();
        return Ok(symbols);
    }

    Err(last_err
        .unwrap_or_else(|| {
            IoError::new(
                ErrorKind::NotFound,
                "available_filter_functions not found in tracefs",
            )
        })
        .into())
}

fn build_function_signatures_from_btf(
    btf: &Btf,
) -> ProbeCatalogResult<HashMap<String, FunctionSignature>> {
    fn type_name_or<'a>(btf: &Btf, ty: &dyn BtfType, fallback: &'a str) -> String {
        btf.resolve_name(ty)
            .ok()
            .filter(|name| !name.is_empty())
            .unwrap_or_else(|| fallback.to_string())
    }

    fn render_type_by_id(btf: &Btf, type_id: u32) -> String {
        let ty = match btf.resolve_type_by_id(type_id) {
            Ok(ty) => ty,
            Err(_) => return format!("type_id_{type_id}"),
        };
        render_type(btf, &ty)
    }

    fn render_type(btf: &Btf, ty: &Type) -> String {
        match ty {
            Type::Void => "void".to_string(),
            Type::Int(i) => {
                if i.is_bool() {
                    return "bool".to_string();
                }
                let named = type_name_or(btf, i, "");
                if !named.is_empty() {
                    named
                } else if i.is_char() {
                    if i.is_signed() {
                        "char".to_string()
                    } else {
                        "unsigned char".to_string()
                    }
                } else {
                    let bits = i.size() * 8;
                    if i.is_signed() {
                        format!("i{bits}")
                    } else {
                        format!("u{bits}")
                    }
                }
            }
            Type::Ptr(p) => {
                let pointee = btf
                    .resolve_chained_type(p)
                    .ok()
                    .map(|inner| render_type(btf, &inner))
                    .unwrap_or_else(|| "void".to_string());
                format!("{pointee} *")
            }
            Type::Array(a) => {
                let item = render_type_by_id(btf, a.get_type_id().unwrap_or(0));
                format!("{item}[{}]", a.len())
            }
            Type::Struct(s) => format!("struct {}", type_name_or(btf, s, "<anon>")),
            Type::Union(u) => format!("union {}", type_name_or(btf, u, "<anon>")),
            Type::Enum(e) => format!("enum {}", type_name_or(btf, e, "<anon>")),
            Type::Enum64(e) => format!("enum64 {}", type_name_or(btf, e, "<anon>")),
            Type::Fwd(f) => {
                if f.is_union() {
                    format!("union {}", type_name_or(btf, f, "<fwd>"))
                } else {
                    format!("struct {}", type_name_or(btf, f, "<fwd>"))
                }
            }
            Type::Typedef(td) => type_name_or(btf, td, "typedef"),
            Type::TypeTag(tt) => {
                let base = render_type_by_id(btf, tt.get_type_id().unwrap_or(0));
                format!("type_tag {base}")
            }
            Type::Volatile(v) => {
                let base = render_type_by_id(btf, v.get_type_id().unwrap_or(0));
                format!("volatile {base}")
            }
            Type::Const(c) => {
                let base = render_type_by_id(btf, c.get_type_id().unwrap_or(0));
                format!("const {base}")
            }
            Type::Restrict(r) => {
                let base = render_type_by_id(btf, r.get_type_id().unwrap_or(0));
                format!("restrict {base}")
            }
            Type::Float(f) => {
                let named = type_name_or(btf, f, "");
                if !named.is_empty() {
                    named
                } else {
                    format!("f{}", f.size() * 8)
                }
            }
            Type::FuncProto(fp) => {
                let ret = render_type_by_id(btf, fp.return_type_id());
                format!("fn(...) -> {ret}")
            }
            Type::Func(fun) => type_name_or(btf, fun, "func"),
            Type::Var(v) => format!("var {}", type_name_or(btf, v, "<anon>")),
            Type::Datasec(ds) => format!("datasec {}", type_name_or(btf, ds, "<anon>")),
            Type::DeclTag(dt) => format!("decl_tag {}", type_name_or(btf, dt, "<anon>")),
        }
    }

    let mut by_name = HashMap::new();
    let ids = (1..u32::MAX)
        .map_while(|id| btf.resolve_type_by_id(id).ok().map(|ty| (id, ty)))
        .collect::<Vec<_>>();
    for (_, ty) in ids {
        let Type::Func(func) = ty else {
            continue;
        };
        let symbol = match btf.resolve_name(&func) {
            Ok(name) if !name.is_empty() => name,
            _ => continue,
        };
        let proto = match btf.resolve_chained_type(&func) {
            Ok(Type::FuncProto(proto)) => proto,
            _ => continue,
        };
        let return_type = render_type_by_id(btf, proto.return_type_id());
        let args = proto
            .parameters
            .iter()
            .enumerate()
            .filter(|(_, param)| !param.is_variadic())
            .map(|(idx, param)| {
                let name = btf
                    .resolve_name(param)
                    .ok()
                    .filter(|value| !value.is_empty())
                    .unwrap_or_else(|| format!("arg{idx}"));
                let arg_type = render_type_by_id(btf, param.get_type_id().unwrap_or(0));
                let unsupported_reason = supported_integer_type_reason(&arg_type);
                ProbeSchemaArg {
                    name,
                    arg_type,
                    is_supported: unsupported_reason.is_none(),
                    unsupported_reason,
                }
            })
            .collect::<Vec<_>>();

        by_name.insert(
            symbol,
            FunctionSignature {
                return_type: Some(return_type),
                args,
            },
        );
    }
    Ok(by_name)
}

fn build_function_probe_schemas(
    symbols: &[FunctionCandidate],
    signatures: &HashMap<String, FunctionSignature>,
) -> Vec<ProbeSchema> {
    let mut probes = Vec::with_capacity(symbols.len() * 6);
    for candidate in symbols {
        let symbol = candidate.symbol.clone();
        let signature = signatures.get(&symbol).cloned().unwrap_or_default();
        for (kind, provider) in [
            (ProbeSchemaKind::Fentry, "fentry"),
            (ProbeSchemaKind::Fexit, "fexit"),
        ] {
            let return_unsupported_reason = signature
                .return_type
                .as_ref()
                .and_then(|ty| supported_integer_type_reason(ty));
            probes.push(ProbeSchema {
                display_name: format!("{provider}:{symbol}"),
                provider: provider.to_string(),
                target: candidate.category.clone(),
                probe: symbol.clone(),
                symbol: Some(symbol.clone()),
                kind: kind.clone(),
                source: ProbeSchemaSource::KernelBtf,
                return_type: signature.return_type.clone(),
                return_supported: return_unsupported_reason.is_none(),
                return_unsupported_reason,
                args: signature.args.clone(),
                fields: Vec::new(),
            });
        }
    }
    probes
}

fn kind_rank(kind: &ProbeSchemaKind) -> u8 {
    match kind {
        ProbeSchemaKind::Tracepoint => 0,
        ProbeSchemaKind::Fentry => 1,
        ProbeSchemaKind::Fexit => 2,
    }
}

fn sort_probe_index(probes: &mut [ProbeIndexEntry]) {
    probes.sort_by(|a, b| {
        a.schema
            .probe
            .cmp(&b.schema.probe)
            .then_with(|| a.schema.target.cmp(&b.schema.target))
            .then_with(|| kind_rank(&a.schema.kind).cmp(&kind_rank(&b.schema.kind)))
            .then_with(|| a.schema.provider.cmp(&b.schema.provider))
            .then_with(|| a.schema.display_name.cmp(&b.schema.display_name))
    });
}

fn get_probe_index_state() -> Arc<ProbeIndexState> {
    PROBE_INDEX
        .get_or_init(|| Arc::new(ProbeIndexState::default()))
        .clone()
}

fn ensure_probe_index_loading() {
    let state = get_probe_index_state();
    if state
        .started
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        return;
    }

    std::thread::spawn(move || {
        let run = || -> ProbeCatalogResult<()> {
            let events_root = tracepoint_format::detect_tracefs_events_root()?;
            let specs = discover_tracepoints(events_root)?;

            let mut chunk = Vec::with_capacity(512);
            for (category, probe) in specs {
                let schema = ProbeSchema {
                    display_name: format!("tracepoint:{category}:{probe}"),
                    provider: "tracepoint".to_string(),
                    target: category,
                    probe,
                    symbol: None,
                    kind: ProbeSchemaKind::Tracepoint,
                    source: ProbeSchemaSource::TraceFsFormat,
                    return_type: None,
                    return_supported: true,
                    return_unsupported_reason: None,
                    args: Vec::new(),
                    fields: Vec::new(),
                };
                chunk.push(ProbeIndexEntry {
                    search_text: probe_search_text(&schema).into(),
                    schema,
                });
                if chunk.len() >= 512 {
                    let mut entries = state
                        .entries
                        .lock()
                        .map_err(|_| IoError::other("failed to lock probe index entries"))?;
                    entries.extend(chunk.drain(..));
                }
            }
            if !chunk.is_empty() {
                let mut entries = state
                    .entries
                    .lock()
                    .map_err(|_| IoError::other("failed to lock probe index entries"))?;
                entries.extend(chunk.drain(..));
            }

            if let Ok(btf) = Btf::from_file("/sys/kernel/btf/vmlinux")
                && let Ok(symbols) = parse_available_filter_functions()
            {
                let signatures = build_function_signatures_from_btf(&btf).unwrap_or_default();
                let function_probes = build_function_probe_schemas(&symbols, &signatures);
                let function_entries = function_probes
                    .into_iter()
                    .map(|schema| ProbeIndexEntry {
                        search_text: probe_search_text(&schema).into(),
                        schema,
                    })
                    .collect::<Vec<_>>();
                let mut entries = state
                    .entries
                    .lock()
                    .map_err(|_| IoError::other("failed to lock probe index entries"))?;
                entries.extend(function_entries);
            }

            let mut entries = state
                .entries
                .lock()
                .map_err(|_| IoError::other("failed to lock probe index entries"))?;
            sort_probe_index(&mut entries);
            Ok(())
        };

        if let Err(error) = run()
            && let Ok(mut err_slot) = state.error.lock()
        {
            *err_slot = Some(error.to_string());
        }
        state.ready.store(true, Ordering::SeqCst);
    });
}

fn get_tracepoint_field_cache() -> &'static Mutex<HashMap<String, Vec<ProbeSchemaField>>> {
    TRACEPOINT_FIELD_CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

fn load_tracepoint_fields(schema: &ProbeSchema) -> ProbeCatalogResult<Vec<ProbeSchemaField>> {
    let cache = get_tracepoint_field_cache();
    if let Some(cached) = cache
        .lock()
        .map_err(|_| IoError::other("failed to lock tracepoint field cache"))?
        .get(&schema.display_name)
        .cloned()
    {
        return Ok(cached);
    }

    let fields = tracepoint_format::load_tracepoint_fields(&schema.target, &schema.probe)?
        .into_iter()
        .map(|field| {
            let field_type_lower = field.field_type.to_ascii_lowercase();
            let unsupported_reason = if field_type_lower.contains("void") {
                Some(format!(
                    "unsupported type '{}'; void-typed fields are not supported",
                    field.field_type
                ))
            } else {
                match field.size {
                    1 | 2 | 4 | 8 => None,
                    _ => Some(format!(
                        "unsupported field size {}; only 1/2/4/8-byte scalar fields are supported",
                        field.size
                    )),
                }
            };
            ProbeSchemaField {
                declaration: field.declaration,
                name: field.name,
                field_type: field.field_type,
                offset: field.offset,
                size: field.size,
                is_signed: field.is_signed,
                is_common: field.is_common,
                is_supported: unsupported_reason.is_none(),
                unsupported_reason,
            }
        })
        .collect::<Vec<_>>();
    cache
        .lock()
        .map_err(|_| IoError::other("failed to lock tracepoint field cache"))?
        .insert(schema.display_name.clone(), fields.clone());
    Ok(fields)
}

fn probe_matches_query(probe: &ProbeSchema, query: &ProbeSchemasQuery) -> bool {
    if let Some(category) = query.category.as_deref()
        && probe.target != category
    {
        return false;
    }
    if let Some(provider) = query.provider.as_deref()
        && probe.provider != provider
    {
        return false;
    }
    if let Some(kinds) = &query.kinds
        && !kinds.iter().any(|kind| kind == &probe.kind)
    {
        return false;
    }
    if let Some(source) = &query.source
        && &probe.source != source
    {
        return false;
    }
    true
}

fn probe_search_text(probe: &ProbeSchema) -> String {
    probe.probe.clone()
}

fn search_kind_boost(kind: &ProbeSchemaKind) -> u32 {
    match kind {
        ProbeSchemaKind::Tracepoint => 500,
        ProbeSchemaKind::Fentry | ProbeSchemaKind::Fexit => 0,
    }
}

fn contains_case_insensitive(haystack: &str, needle: &str) -> bool {
    if needle.is_empty() {
        return true;
    }
    haystack
        .to_ascii_lowercase()
        .contains(&needle.to_ascii_lowercase())
}

pub async fn query_probe_schemas_page(
    query: ProbeSchemasQuery,
) -> ProbeCatalogResult<ProbeSchemasPageResponse> {
    if query.limit == 0 {
        return Err(IoError::new(ErrorKind::InvalidInput, "limit must be > 0").into());
    }

    ensure_probe_index_loading();
    let state = get_probe_index_state();

    if let Some(error) = state
        .error
        .lock()
        .map_err(|_| IoError::other("failed to lock probe index error"))?
        .clone()
    {
        return Err(IoError::other(error).into());
    }

    let is_loading = !state.ready.load(Ordering::SeqCst);
    let entries = state
        .entries
        .lock()
        .map_err(|_| IoError::other("failed to lock probe index entries"))?;
    let mut matching = entries
        .iter()
        .filter(|entry| probe_matches_query(&entry.schema, &query))
        .collect::<Vec<&ProbeIndexEntry>>();
    if let Some(search) = query.search.as_deref() {
        let trimmed = search.trim();
        if !trimmed.is_empty() {
            let mut matcher = Matcher::new(Config::DEFAULT);
            let pattern = Pattern::parse(trimmed, CaseMatching::Ignore, Normalization::Smart);
            let mut scored = matching
                .into_iter()
                .filter_map(|entry| {
                    let score = pattern.score(entry.search_text.slice(..), &mut matcher)?;
                    let substring_match = contains_case_insensitive(&entry.schema.probe, trimmed);
                    let kind_boost = if substring_match {
                        search_kind_boost(&entry.schema.kind)
                    } else {
                        0
                    };
                    let boosted = score.saturating_add(kind_boost);
                    Some((boosted, score, entry))
                })
                .collect::<Vec<_>>();
            scored.sort_by(
                |(boosted_a, score_a, entry_a), (boosted_b, score_b, entry_b)| {
                    boosted_b.cmp(boosted_a).then_with(|| {
                        score_b.cmp(score_a).then_with(|| {
                            entry_a
                                .schema
                                .display_name
                                .cmp(&entry_b.schema.display_name)
                                .then_with(|| entry_a.schema.target.cmp(&entry_b.schema.target))
                                .then_with(|| {
                                    kind_rank(&entry_a.schema.kind)
                                        .cmp(&kind_rank(&entry_b.schema.kind))
                                })
                        })
                    })
                },
            );
            matching = scored.into_iter().map(|(_, _, entry)| entry).collect();
        }
    }
    let total = matching.len();
    let page = matching
        .into_iter()
        .skip(query.offset)
        .take(query.limit)
        .map(|entry| {
            let mut cloned = entry.schema.clone();
            if query.include_fields && cloned.kind == ProbeSchemaKind::Tracepoint {
                cloned.fields = load_tracepoint_fields(&cloned)?;
            } else {
                cloned.fields = Vec::new();
            }
            Ok(cloned)
        })
        .collect::<ProbeCatalogResult<Vec<_>>>()?;

    Ok(ProbeSchemasPageResponse {
        has_more: query.offset.saturating_add(page.len()) < total || is_loading,
        probes: page,
        total,
        offset: query.offset,
        limit: query.limit,
        is_loading,
    })
}

pub async fn query_probe_schema_detail(display_name: String) -> ProbeCatalogResult<ProbeSchema> {
    ensure_probe_index_loading();
    let state = get_probe_index_state();

    if let Some(error) = state
        .error
        .lock()
        .map_err(|_| IoError::other("failed to lock probe index error"))?
        .clone()
    {
        return Err(IoError::other(error).into());
    }

    let entries = state
        .entries
        .lock()
        .map_err(|_| IoError::other("failed to lock probe index entries"))?;
    let schema = entries
        .iter()
        .find(|entry| entry.schema.display_name == display_name)
        .ok_or_else(|| {
            if !state.ready.load(Ordering::SeqCst) {
                IoError::new(
                    ErrorKind::WouldBlock,
                    format!("probe schema not loaded yet: {}", display_name),
                )
            } else {
                IoError::new(
                    ErrorKind::NotFound,
                    format!("probe schema not found: {}", display_name),
                )
            }
        })?
        .schema
        .clone();

    if schema.kind == ProbeSchemaKind::Tracepoint {
        let mut with_fields = schema.clone();
        with_fields.fields = load_tracepoint_fields(&schema)?;
        return Ok(with_fields);
    }

    Ok(schema)
}

pub async fn query_probe_schemas() -> ProbeCatalogResult<ProbeSchemasResponse> {
    ensure_probe_index_loading();
    let state = get_probe_index_state();
    let entries = state
        .entries
        .lock()
        .map_err(|_| IoError::other("failed to lock probe index entries"))?;
    Ok(ProbeSchemasResponse {
        probes: entries.iter().map(|entry| entry.schema.clone()).collect(),
    })
}

pub fn has_function_probes_loaded() -> ProbeCatalogResult<bool> {
    ensure_probe_index_loading();
    let state = get_probe_index_state();
    if let Some(error) = state
        .error
        .lock()
        .map_err(|_| IoError::other("failed to lock probe index error"))?
        .clone()
    {
        return Err(IoError::other(error).into());
    }
    let entries = state
        .entries
        .lock()
        .map_err(|_| IoError::other("failed to lock probe index entries"))?;
    Ok(entries.iter().any(|entry| {
        matches!(
            entry.schema.kind,
            ProbeSchemaKind::Fentry | ProbeSchemaKind::Fexit
        )
    }))
}
