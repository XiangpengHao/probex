use crate::tracepoint_format;
use aya::Btf;
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
    entries: Mutex<Vec<ProbeSchema>>,
    error: Mutex<Option<String>>,
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

pub fn initialize_probe_index_loading() {
    ensure_probe_index_loading();
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
    let signatures = btf.function_signatures().map_err(|error| {
        IoError::other(format!(
            "failed to parse function signatures from BTF: {error}"
        ))
    })?;
    let mut by_name = HashMap::with_capacity(signatures.len());
    for (symbol, return_type, params) in signatures {
        let args = params
            .into_iter()
            .enumerate()
            .map(|(idx, (name, arg_type))| {
                let unsupported_reason = supported_integer_type_reason(&arg_type);
                ProbeSchemaArg {
                    name: if name.is_empty() {
                        format!("arg{idx}")
                    } else {
                        name
                    },
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

fn sort_probe_index(probes: &mut [ProbeSchema]) {
    probes.sort_by(|a, b| {
        a.probe
            .cmp(&b.probe)
            .then_with(|| a.target.cmp(&b.target))
            .then_with(|| kind_rank(&a.kind).cmp(&kind_rank(&b.kind)))
            .then_with(|| a.provider.cmp(&b.provider))
            .then_with(|| a.display_name.cmp(&b.display_name))
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
                chunk.push(ProbeSchema {
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

            if let Ok(btf) = Btf::from_sys_fs()
                && let Ok(symbols) = parse_available_filter_functions()
            {
                let signatures = build_function_signatures_from_btf(&btf).unwrap_or_default();
                let function_probes = build_function_probe_schemas(&symbols, &signatures);
                let mut entries = state
                    .entries
                    .lock()
                    .map_err(|_| IoError::other("failed to lock probe index entries"))?;
                entries.extend(function_probes);
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
    if let Some(search) = query.search.as_deref() {
        let q = search.to_ascii_lowercase();
        let mut haystacks = vec![
            probe.display_name.to_ascii_lowercase(),
            probe.provider.to_ascii_lowercase(),
            probe.target.to_ascii_lowercase(),
            probe.probe.to_ascii_lowercase(),
        ];
        if let Some(symbol) = &probe.symbol {
            haystacks.push(symbol.to_ascii_lowercase());
        }
        if !haystacks.iter().any(|value| value.contains(&q)) {
            return false;
        }
    }
    true
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
    let matching = entries
        .iter()
        .filter(|probe| probe_matches_query(probe, &query))
        .collect::<Vec<&ProbeSchema>>();
    let total = matching.len();
    let page = matching
        .into_iter()
        .skip(query.offset)
        .take(query.limit)
        .map(|probe| {
            let mut cloned = probe.clone();
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
        .find(|probe| probe.display_name == display_name)
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
        probes: entries.clone(),
    })
}
