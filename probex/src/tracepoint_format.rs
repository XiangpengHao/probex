use std::error::Error;
use std::fs;
use std::io::{Error as IoError, ErrorKind};
use std::path::{Path, PathBuf};

pub(crate) type TracepointFormatResult<T> = Result<T, Box<dyn Error + Send + Sync>>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ParsedTracepointField {
    pub(crate) declaration: String,
    pub(crate) name: String,
    pub(crate) field_type: String,
    pub(crate) offset: u32,
    pub(crate) size: u32,
    pub(crate) is_signed: bool,
    pub(crate) is_common: bool,
}

pub(crate) fn detect_tracefs_events_root() -> TracepointFormatResult<&'static Path> {
    const CANDIDATES: &[&str] = &[
        "/sys/kernel/tracing/events",
        "/sys/kernel/debug/tracing/events",
    ];

    for candidate in CANDIDATES {
        let path = Path::new(candidate);
        if path.exists() {
            return Ok(path);
        }
    }

    Err(IoError::new(
        ErrorKind::NotFound,
        "tracefs events root not found at /sys/kernel/tracing/events or /sys/kernel/debug/tracing/events",
    )
    .into())
}

pub(crate) fn tracepoint_format_path(events_root: &Path, category: &str, name: &str) -> PathBuf {
    events_root.join(category).join(name).join("format")
}

fn parse_field_declaration(declaration: &str) -> TracepointFormatResult<(String, String)> {
    let normalized = declaration.trim();
    let raw_var_token = normalized.split_whitespace().last().ok_or_else(|| {
        IoError::new(
            ErrorKind::InvalidData,
            format!("invalid tracepoint field declaration: '{normalized}'"),
        )
    })?;
    let stars = raw_var_token.chars().take_while(|ch| *ch == '*').count();
    let var_without_stars = &raw_var_token[stars..];
    let (name_token, array_suffix) = if let Some(array_pos) = var_without_stars.find('[') {
        (
            &var_without_stars[..array_pos],
            &var_without_stars[array_pos..],
        )
    } else {
        (var_without_stars, "")
    };
    let name = name_token.trim().to_string();
    if name.is_empty() {
        return Err(IoError::new(
            ErrorKind::InvalidData,
            format!("unable to parse field name from declaration '{normalized}'"),
        )
        .into());
    }

    let var_pos = normalized.rfind(raw_var_token).ok_or_else(|| {
        IoError::new(
            ErrorKind::InvalidData,
            format!("unable to locate variable token in declaration '{normalized}'"),
        )
    })?;
    let mut field_type = normalized[..var_pos].trim().to_string();
    if stars > 0 {
        if !field_type.is_empty() {
            field_type.push(' ');
        }
        field_type.push_str(&"*".repeat(stars));
    }
    if !array_suffix.is_empty() {
        field_type.push_str(array_suffix);
    }
    if field_type.is_empty() {
        return Err(IoError::new(
            ErrorKind::InvalidData,
            format!("unable to parse field type from declaration '{normalized}'"),
        )
        .into());
    }

    Ok((name, field_type))
}

pub(crate) fn parse_tracepoint_format_fields(
    format_contents: &str,
) -> TracepointFormatResult<Vec<ParsedTracepointField>> {
    let mut in_format_block = false;
    let mut fields = Vec::new();

    for raw_line in format_contents.lines() {
        let trimmed = raw_line.trim();
        if !in_format_block {
            if trimmed == "format:" {
                in_format_block = true;
            }
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix("field:") {
            let declaration = rest
                .split(';')
                .next()
                .map(str::trim)
                .unwrap_or_default()
                .to_string();
            if declaration.is_empty() {
                return Err(IoError::new(
                    ErrorKind::InvalidData,
                    "tracepoint format contains field entry with empty declaration",
                )
                .into());
            }

            let offset = trimmed
                .split(';')
                .map(str::trim)
                .find_map(|item| item.strip_prefix("offset:"))
                .ok_or_else(|| {
                    IoError::new(
                        ErrorKind::InvalidData,
                        format!("tracepoint field '{declaration}' missing offset"),
                    )
                })?
                .parse::<u32>()
                .map_err(|error| {
                    IoError::new(
                        ErrorKind::InvalidData,
                        format!("tracepoint field '{declaration}' has invalid offset: {error}"),
                    )
                })?;
            let size = trimmed
                .split(';')
                .map(str::trim)
                .find_map(|item| item.strip_prefix("size:"))
                .ok_or_else(|| {
                    IoError::new(
                        ErrorKind::InvalidData,
                        format!("tracepoint field '{declaration}' missing size"),
                    )
                })?
                .parse::<u32>()
                .map_err(|error| {
                    IoError::new(
                        ErrorKind::InvalidData,
                        format!("tracepoint field '{declaration}' has invalid size: {error}"),
                    )
                })?;
            let signed_raw = trimmed
                .split(';')
                .map(str::trim)
                .find_map(|item| item.strip_prefix("signed:"))
                .ok_or_else(|| {
                    IoError::new(
                        ErrorKind::InvalidData,
                        format!("tracepoint field '{declaration}' missing signed"),
                    )
                })?
                .parse::<u8>()
                .map_err(|error| {
                    IoError::new(
                        ErrorKind::InvalidData,
                        format!(
                            "tracepoint field '{declaration}' has invalid signed flag: {error}"
                        ),
                    )
                })?;
            if signed_raw > 1 {
                return Err(IoError::new(
                    ErrorKind::InvalidData,
                    format!(
                        "tracepoint field '{declaration}' has unexpected signed flag value {signed_raw}"
                    ),
                )
                .into());
            }

            let (name, field_type) = parse_field_declaration(&declaration)?;
            fields.push(ParsedTracepointField {
                declaration: declaration.clone(),
                name: name.clone(),
                field_type,
                offset,
                size,
                is_signed: signed_raw == 1,
                is_common: name.starts_with("common_"),
            });
        }
    }

    if !in_format_block {
        return Err(IoError::new(
            ErrorKind::InvalidData,
            "tracepoint format file missing required 'format:' section",
        )
        .into());
    }
    if fields.is_empty() {
        return Err(IoError::new(
            ErrorKind::InvalidData,
            "tracepoint format contains no parseable fields",
        )
        .into());
    }

    Ok(fields)
}

pub(crate) fn load_tracepoint_fields(
    category: &str,
    probe: &str,
) -> TracepointFormatResult<Vec<ParsedTracepointField>> {
    let events_root = detect_tracefs_events_root()?;
    let format_path = tracepoint_format_path(events_root, category, probe);
    let format_contents = fs::read_to_string(&format_path).map_err(|error| {
        IoError::new(
            ErrorKind::NotFound,
            format!(
                "failed to read tracepoint format '{}': {}",
                format_path.display(),
                error
            ),
        )
    })?;
    parse_tracepoint_format_fields(&format_contents)
}
