//! Layer de formatage JSON pour tracing
//!
//! Ce module provides un layer personnalise pour le crate `tracing`
//! that formats events as structured JSON.

use std::collections::HashMap;
use std::fmt;
use std::io::Write;
use std::sync::Mutex;

use serde::Serialize;
use tracing::{Event, Level, Subscriber};
use tracing_subscriber::fmt::format::Writer;
use tracing_subscriber::fmt::time::FormatTime;
use tracing_subscriber::fmt::{FmtContext, FormatFields};
use tracing_subscriber::layer::{Context, Layer};
use tracing_subscriber::registry::LookupSpan;

use super::Result;

/// JSON output format for logs
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JsonFormat {
    /// JSON compact (une ligne par event)
    Compact,
    /// JSON pretty-printe (pour le developpement)
    Pretty,
}

impl Default for JsonFormat {
    fn default() -> Self {
        JsonFormat::Compact
    }
}

/// Layer de formatage JSON pour tracing
pub struct JsonLayer<W> {
    writer: Mutex<W>,
    format: JsonFormat,
    include_span_context: bool,
    include_thread_info: bool,
    include_target: bool,
}

impl<W: Write + Send + 'static> JsonLayer<W> {
    /// Creates a nouveau layer JSON
    pub fn new(writer: W) -> Self {
        Self {
            writer: Mutex::new(writer),
            format: JsonFormat::Compact,
            include_span_context: true,
            include_thread_info: false,
            include_target: true,
        }
    }

    /// Defines the output format
    pub fn with_format(mut self, format: JsonFormat) -> Self {
        self.format = format;
        self
    }

    /// Enables/disables span context inclusion
    pub fn with_span_context(mut self, enabled: bool) -> Self {
        self.include_span_context = enabled;
        self
    }

    /// Enables/disables thread information inclusion
    pub fn with_thread_info(mut self, enabled: bool) -> Self {
        self.include_thread_info = enabled;
        self
    }

    /// Enables/disables target inclusion
    pub fn with_target(mut self, enabled: bool) -> Self {
        self.include_target = enabled;
        self
    }

    /// Formats an event as JSON
    fn format_event_json<S, N>(
        &self,
        ctx: &FmtContext<'S, N>,
        event: &Event,
    ) -> serde_json::Result<String>
    where
        S: Subscriber + for <a> LookupSpan<'a>,
        N: for <a> FormatFields<'a>,
    {
        let mut log_entry = JsonLogEntry::default();

        // Timestamp
        log_entry.timestamp = chrono::Utc::now().to_rfc3339();

        // Niveau de log
        log_entry.level = event.metadata().level().to_string();

        // Cible (module)
        if self.include_target {
            log_entry.target = Some(event.metadata().target().to_string());
        }

        // Nom de l'event
        log_entry.name = event.metadata().name().to_string();

        // Thread info
        if self.include_thread_info {
            log_entry.thread_id = Some(format!("{:?}", std::thread::current().id()));
            if let Some(name) = std::thread::current().name() {
                log_entry.thread_name = Some(name.to_string());
            }
        }

        // Champs de l'event
        let mut visitor = JsonVisitor::default();
        event.record(&mut visitor);
        log_entry.fields = visitor.fields;
        log_entry.message = visitor.message;

        // Contexte de span
        if self.include_span_context {
            if let Some(scope) = ctx.event_scope(event) {
                let spans: Vec<String> = scope
                    .from_root()
                    .map(|span| span.name().to_string())
                    .collect();
                if !spans.is_empty() {
                    log_entry.spans = Some(spans);
                }
            }
        }

        // Serialize according to format
        match self.format {
            JsonFormat::Compact => serde_json::to_string(&log_entry),
            JsonFormat::Pretty => serde_json::to_string_pretty(&log_entry),
        }
    }
}

impl<S, W> Layer<S> for JsonLayer<W>
where
    S: Subscriber + for <a> LookupSpan<'a>,
    W: Write + Send + 'static,
{
    fn on_event(
        &self,
        event: &Event,
        ctx: Context<'S>,
    ) {
        // Create a formatting context
        let fmt_ctx = FmtContext::new(&ctx,
            &tracing_subscriber::fmt::format::DefaultFields::default(),
        );

        match self.format_event_json(&fmt_ctx, event) {
            Ok(json) => {
                let mut writer = match self.writer.lock() {
                    Ok(guard) => guard,
                    Err(_) => return,
                };

                if writeln!(writer, "{}", json).is_err() {
                    // Ignore write errors
                }
            }
            Err(_) => {
                // Ignore serialization errors
            }
        }
    }
}

/// JSON format log entry
#[derive(Debug, Default, Serialize)]
struct JsonLogEntry {
    /// Timestamp ISO8601
    timestamp: String,
    /// Niveau de log (TRACE, DEBUG, INFO, WARN, ERROR)
    level: String,
    /// Log target (module)
    #[serde(skip_serializing_if = "Option::is_none")]
    target: Option<String>,
    /// Nom de l'event
    name: String,
    /// Message formate
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<String>,
    /// Champs additionnels
    #[serde(flatten)]
    fields: HashMap<String, serde_json::Value>,
    /// Thread ID
    #[serde(skip_serializing_if = "Option::is_none")]
    thread_id: Option<String>,
    /// Thread name
    #[serde(skip_serializing_if = "Option::is_none")]
    thread_name: Option<String>,
    /// Pile de spans
    #[serde(skip_serializing_if = "Option::is_none")]
    spans: Option<Vec<String>>,
}

/// Visitor for extracting event fields
#[derive(Default)]
struct JsonVisitor {
    fields: HashMap<String, serde_json::Value>,
    message: Option<String>,
}

impl tracing::field::Visit for JsonVisitor {
    fn record_debug(&mut self,
        field: &tracing::field::Field,
        value: &dyn fmt::Debug,
    ) {
        let key = field.name().to_string();
        let json_value = format!("{:?}", value);
        
        // Le champ "message" est traite specialement
        if key == "message" {
            self.message = Some(json_value.trim_matches('"').to_string());
        } else {
            self.fields.insert(
                key,
                serde_json::Value::String(json_value),
            );
        }
    }

    fn record_str(
        &mut self,
        field: &tracing::field::Field,
        value: &str,
    ) {
        let key = field.name().to_string();
        if key == "message" {
            self.message = Some(value.to_string());
        } else {
            self.fields.insert(
                key,
                serde_json::Value::String(value.to_string()),
            );
        }
    }

    fn record_i64(
        &mut self,
        field: &tracing::field::Field,
        value: i64,
    ) {
        self.fields.insert(
            field.name().to_string(),
            serde_json::Value::Number(value.into()),
        );
    }

    fn record_u64(
        &mut self,
        field: &tracing::field::Field,
        value: u64,
    ) {
        self.fields.insert(
            field.name().to_string(),
            serde_json::Value::Number(value.into()),
        );
    }

    fn record_f64(
        &mut self,
        field: &tracing::field::Field,
        value: f64,
    ) {
        if let Some(num) = serde_json::Number::from_f64(value) {
            self.fields.insert(
                field.name().to_string(),
                serde_json::Value::Number(num),
            );
        }
    }

    fn record_bool(
        &mut self,
        field: &tracing::field::Field,
        value: bool,
    ) {
        self.fields.insert(
            field.name().to_string(),
            serde_json::Value::Bool(value),
        );
    }
}

/// JSON formatting layer for console
pub struct ConsoleJsonLayer {
    format: JsonFormat,
    include_span_context: bool,
    include_target: bool,
}

impl ConsoleJsonLayer {
    /// Creates a new JSON layer for console
    pub fn new() -> Self {
        Self {
            format: JsonFormat::Compact,
            include_span_context: true,
            include_target: true,
        }
    }

    /// Defines the output format
    pub fn with_format(mut self, format: JsonFormat) -> Self {
        self.format = format;
        self
    }
}

impl<S> Layer<S> for ConsoleJsonLayer
where
    S: Subscriber + for <a> LookupSpan<'a>,
{
    fn on_event(
        &self,
        event: &Event,
        ctx: Context<'S>,
    ) {
        let mut log_entry = JsonLogEntry::default();

        // Timestamp
        log_entry.timestamp = chrono::Utc::now().to_rfc3339();

        // Niveau de log
        log_entry.level = event.metadata().level().to_string();

        // Cible
        if self.include_target {
            log_entry.target = Some(event.metadata().target().to_string());
        }

        // Nom
        log_entry.name = event.metadata().name().to_string();

        // Champs
        let mut visitor = JsonVisitor::default();
        event.record(&mut visitor);
        log_entry.fields = visitor.fields;
        log_entry.message = visitor.message;

        // Contexte de span
        if self.include_span_context {
            if let Some(scope) = ctx.event_scope(event) {
                let spans: Vec<String> = scope
                    .from_root()
                    .map(|span| span.name().to_string())
                    .collect();
                if !spans.is_empty() {
                    log_entry.spans = Some(spans);
                }
            }
        }

        // Afficher
        let output = match self.format {
            JsonFormat::Compact => serde_json::to_string(&log_entry).unwrap_or_default(),
            JsonFormat::Pretty => serde_json::to_string_pretty(&log_entry).unwrap_or_default(),
        };

        println!("{}", output);
    }
}

impl Default for ConsoleJsonLayer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_json_visitor() {
        // Ce test checks que le JsonVisitor fonctionne correctement
        // Note: Complete tests would require a tracing subscriber
        
        let mut visitor = JsonVisitor::default();
        
        // Simuler l'enregistrement de champs
        // In a real test, one would use event.record()
        
        assert!(visitor.fields.is_empty());
        assert!(visitor.message.is_none());
    }

    #[test]
    fn test_json_log_entry_serialization() {
        let entry = JsonLogEntry {
            timestamp: "2024-01-01T00:00:00Z".to_string(),
            level: "INFO".to_string(),
            target: Some("test::module".to_string()),
            name: "test_event".to_string(),
            message: Some("Test message".to_string()),
            fields: {
                let mut map = HashMap::new();
                map.insert("key".to_string(), serde_json::json!("value"));
                map
            },
            thread_id: None,
            thread_name: None,
            spans: Some(vec!["span1".to_string(), "span2".to_string()]),
        };

        let json = serde_json::to_string(&entry).unwrap();
        assert!(json.contains("timestamp"));
        assert!(json.contains("2024-01-01T00:00:00Z"));
        assert!(json.contains("INFO"));
        assert!(json.contains("Test message"));
        assert!(json.contains("span1"));
        assert!(json.contains("span2"));
    }

    #[test]
    fn test_json_format_default() {
        let format: JsonFormat = Default::default();
        assert_eq!(format, JsonFormat::Compact);
    }

    #[test]
    fn test_console_json_layer_builder() {
        let layer = ConsoleJsonLayer::new()
            .with_format(JsonFormat::Pretty);
        
        // Check that le layer est cree correctement
        assert_eq!(layer.format, JsonFormat::Pretty);
    }
}
