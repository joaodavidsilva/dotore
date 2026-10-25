//! Static cursor parser for `dotore.config.{ts,js,mjs,cjs}` module exports.

use std::collections::HashMap;

use serde_json::{Map, Value};

use crate::ir::ByteSpan;

#[derive(Debug, Clone)]
pub(in crate::config) struct ParsedObject {
    pub(in crate::config) span: ByteSpan,
    pub(in crate::config) properties: Vec<(String, ByteSpan, ByteSpan)>,
    pub(in crate::config) map: Map<String, Value>,
}

pub(in crate::config) fn parse_exported_module_object(source: &str) -> Result<ParsedObject, String> {
    let mut bindings: HashMap<String, usize> = HashMap::new();
    let mut export_expr_starts: Vec<usize> = Vec::new();

    let mut scanner = ConfigCursor::new(source, HashMap::new());
    while scanner.pos < source.len() {
        scanner.skip_ws_and_comments();
        if scanner.pos >= source.len() {
            break;
        }
        scanner.scan_top_level_statement(&mut bindings, &mut export_expr_starts)?;
    }

    for start_pos in export_expr_starts {
        let mut eval_cursor = ConfigCursor::with_pos(source, start_pos, bindings.clone());
        if let Ok(obj) = eval_cursor.resolve_to_object(0) {
            return Ok(obj);
        }
    }

    Err("Could not statically edit configuration object (dynamic config export)".to_string())
}

pub(in crate::config) struct ConfigCursor<'a> {
    src: &'a str,
    bytes: &'a [u8],
    pub(in crate::config) pos: usize,
    bindings: HashMap<String, usize>,
}

impl<'a> ConfigCursor<'a> {
    pub(in crate::config) const fn new(src: &'a str, bindings: HashMap<String, usize>) -> Self {
        Self {
            src,
            bytes: src.as_bytes(),
            pos: 0,
            bindings,
        }
    }

    pub(in crate::config) const fn with_pos(
        src: &'a str,
        pos: usize,
        bindings: HashMap<String, usize>,
    ) -> Self {
        Self {
            src,
            bytes: src.as_bytes(),
            pos,
            bindings,
        }
    }

    fn scan_top_level_statement(
        &mut self,
        bindings: &mut HashMap<String, usize>,
        export_expr_starts: &mut Vec<usize>,
    ) -> Result<(), String> {
        if self.consume_keyword("import") {
            self.skip_statement();
            return Ok(());
        }
        let is_export = self.consume_keyword("export");
        self.skip_ws_and_comments();
        if is_export && self.consume_keyword("default") {
            self.skip_ws_and_comments();
            if self.peek_keyword("function")
                || self.peek_keyword("class")
                || self.peek_keyword("interface")
            {
                return Err(
                    "Could not statically edit configuration object (dynamic config export)"
                        .to_string(),
                );
            }
            export_expr_starts.push(self.pos);
            self.skip_statement();
            return Ok(());
        }
        if self.consume_keyword("const")
            || self.consume_keyword("let")
            || self.consume_keyword("var")
        {
            self.scan_variable_declaration(bindings);
            return Ok(());
        }
        if let Some(rhs_pos) = self.try_consume_cjs_exports_assignment() {
            export_expr_starts.push(rhs_pos);
            self.skip_statement();
            return Ok(());
        }
        self.advance_token_or_char();
        Ok(())
    }

    fn scan_variable_declaration(&mut self, bindings: &mut HashMap<String, usize>) {
        self.skip_ws_and_comments();
        if let Some(ident) = self.parse_identifier() {
            self.skip_ws_and_comments();
            if self.peek_byte() == Some(b':') {
                self.pos += 1;
                self.skip_type_annotation_before_eq();
            }
            self.skip_ws_and_comments();
            if self.peek_byte() == Some(b'=') {
                self.pos += 1;
                self.skip_ws_and_comments();
                bindings.insert(ident, self.pos);
            }
        }
        self.skip_statement();
    }

    fn peek_byte(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    pub(in crate::config) fn skip_ws_and_comments(&mut self) {
        while let Some(&b) = self.bytes.get(self.pos) {
            if b.is_ascii_whitespace() {
                self.pos += 1;
                continue;
            }
            if b == b'/' && self.bytes.get(self.pos + 1) == Some(&b'/') {
                self.pos += 2;
                while self.bytes.get(self.pos).is_some_and(|&c| c != b'\n') {
                    self.pos += 1;
                }
                continue;
            }
            if b == b'/' && self.bytes.get(self.pos + 1) == Some(&b'*') {
                self.pos += 2;
                while self.pos + 1 < self.bytes.len()
                    && !(self.bytes.get(self.pos) == Some(&b'*')
                        && self.bytes.get(self.pos + 1) == Some(&b'/'))
                {
                    self.pos += 1;
                }
                self.pos = (self.pos + 2).min(self.bytes.len());
                continue;
            }
            break;
        }
    }

    fn peek_keyword(&self, kw: &str) -> bool {
        let kw_bytes = kw.as_bytes();
        let Some(slice) = self.bytes.get(self.pos..self.pos + kw_bytes.len()) else {
            return false;
        };
        if slice != kw_bytes {
            return false;
        }
        let next = self.bytes.get(self.pos + kw_bytes.len()).copied();
        !next.is_some_and(is_ident_continue)
    }

    fn consume_keyword(&mut self, kw: &str) -> bool {
        if self.peek_keyword(kw) {
            self.pos += kw.len();
            true
        } else {
            false
        }
    }

    fn parse_identifier(&mut self) -> Option<String> {
        self.skip_ws_and_comments();
        let first = self.peek_byte()?;
        if !is_ident_start(first) {
            return None;
        }
        let start = self.pos;
        self.pos += 1;
        while let Some(b) = self.peek_byte() {
            if is_ident_continue(b) {
                self.pos += 1;
            } else {
                break;
            }
        }
        self.src.get(start..self.pos).map(str::to_string)
    }

    fn try_consume_cjs_exports_assignment(&mut self) -> Option<usize> {
        let save = self.pos;
        let first = self.parse_identifier()?;
        self.skip_ws_and_comments();
        if self.peek_byte() != Some(b'.') {
            self.pos = save;
            return None;
        }
        self.pos += 1;
        let second = self.parse_identifier()?;
        let valid_target = (first == "module" && second == "exports")
            || (first == "exports" && second == "default");
        if !valid_target {
            self.pos = save;
            return None;
        }
        self.skip_ws_and_comments();
        if self.peek_byte() != Some(b'=') || self.bytes.get(self.pos + 1) == Some(&b'=') {
            self.pos = save;
            return None;
        }
        self.pos += 1;
        self.skip_ws_and_comments();
        Some(self.pos)
    }

    fn skip_type_annotation_before_eq(&mut self) {
        let mut depth = 0_i32;
        while self.pos < self.bytes.len() {
            self.skip_ws_and_comments();
            let Some(b) = self.peek_byte() else {
                break;
            };
            if depth == 0 && b == b'=' {
                break;
            }
            match b {
                b'<' | b'(' | b'[' | b'{' => {
                    depth += 1;
                    self.pos += 1;
                }
                b'>' | b')' | b']' | b'}' => {
                    depth = (depth - 1).max(0);
                    self.pos += 1;
                }
                b'\'' | b'"' | b'`' => {
                    let _ = self.parse_string_literal();
                }
                _ => {
                    self.pos += 1;
                }
            }
        }
    }

    fn skip_statement(&mut self) {
        let mut depth = 0_i32;
        while self.pos < self.bytes.len() {
            self.skip_ws_and_comments();
            let Some(b) = self.peek_byte() else {
                break;
            };
            match b {
                b'{' | b'(' | b'[' => {
                    depth += 1;
                    self.pos += 1;
                }
                b'}' | b')' | b']' => {
                    depth -= 1;
                    self.pos += 1;
                    if depth <= 0 && b == b'}' {
                        self.consume_optional_semicolon();
                        break;
                    }
                }
                b';' if depth <= 0 => {
                    self.pos += 1;
                    break;
                }
                b'\'' | b'"' | b'`' => {
                    let _ = self.parse_string_literal();
                }
                _ => {
                    self.pos += 1;
                }
            }
        }
    }

    fn consume_optional_semicolon(&mut self) {
        self.skip_ws_and_comments();
        if self.peek_byte() == Some(b';') {
            self.pos += 1;
        }
    }

    fn advance_token_or_char(&mut self) {
        self.skip_ws_and_comments();
        let Some(b) = self.peek_byte() else {
            return;
        };
        if matches!(b, b'\'' | b'"' | b'`') {
            if self.parse_string_literal().is_err() {
                self.pos += 1;
            }
            return;
        }
        if let Some(ch) = self.src.get(self.pos..).and_then(|s| s.chars().next()) {
            self.pos += ch.len_utf8();
        } else {
            self.pos += 1;
        }
    }
}

impl ConfigCursor<'_> {
    pub(in crate::config) fn resolve_to_object(
        &mut self,
        depth: usize,
    ) -> Result<ParsedObject, String> {
        if depth > 16 {
            return Err("Config reference recursion limit exceeded".to_string());
        }
        self.skip_ws_and_comments();
        if self.peek_byte() == Some(b'<') {
            self.skip_angle_bracket_type_assertion();
            self.skip_ws_and_comments();
        }
        match self.peek_byte() {
            Some(b'(') => {
                self.pos += 1;
                let obj = self.resolve_to_object(depth + 1)?;
                self.skip_ts_postfix_assertions();
                if self.peek_byte() == Some(b')') {
                    self.pos += 1;
                }
                self.skip_ts_postfix_assertions();
                Ok(obj)
            }
            Some(b'{') => {
                let obj = self.parse_object()?;
                self.skip_ts_postfix_assertions();
                Ok(obj)
            }
            _ => {
                let ident = self
                    .parse_identifier()
                    .ok_or_else(|| "Expected object or config helper".to_string())?;
                self.skip_ws_and_comments();
                if self.peek_byte() == Some(b'<') {
                    self.skip_angle_bracket_type_assertion();
                    self.skip_ws_and_comments();
                }
                if self.peek_byte() == Some(b'(') {
                    self.pos += 1;
                    let obj = self.resolve_to_object(depth + 1)?;
                    self.skip_ts_postfix_assertions();
                    if self.peek_byte() == Some(b')') {
                        self.pos += 1;
                    }
                    self.skip_ts_postfix_assertions();
                    return Ok(obj);
                }
                let target_pos = *self
                    .bindings
                    .get(&ident)
                    .ok_or_else(|| format!("Unresolved config identifier {ident}"))?;
                let mut sub = ConfigCursor::with_pos(self.src, target_pos, self.bindings.clone());
                sub.resolve_to_object(depth + 1)
            }
        }
    }

    pub(in crate::config) fn parse_object(&mut self) -> Result<ParsedObject, String> {
        self.skip_ws_and_comments();
        if self.peek_byte() != Some(b'{') {
            return Err("Expected '{'".to_string());
        }
        let obj_start = u32::try_from(self.pos).unwrap_or(0);
        self.pos += 1;

        let mut properties = Vec::new();
        let mut map = Map::new();

        loop {
            self.skip_ws_and_comments();
            let Some(b) = self.peek_byte() else {
                return Err("Unterminated object literal".to_string());
            };
            if b == b'}' {
                self.pos += 1;
                let obj_end = u32::try_from(self.pos).unwrap_or(obj_start);
                return Ok(ParsedObject {
                    span: ByteSpan {
                        start: obj_start,
                        end: obj_end,
                    },
                    properties,
                    map,
                });
            }
            if b == b',' {
                self.pos += 1;
                continue;
            }

            let prop_start = u32::try_from(self.pos).unwrap_or(0);
            let key = if b == b'\'' || b == b'"' {
                self.parse_string_literal()?
            } else {
                self.parse_identifier()
                    .ok_or_else(|| "Unsupported dynamic or spread object property".to_string())?
            };

            self.skip_ws_and_comments();
            if self.peek_byte() != Some(b':') {
                return Err("Expected ':' after object property key".to_string());
            }
            self.pos += 1;
            self.skip_ws_and_comments();

            let val_start = u32::try_from(self.pos).unwrap_or(0);
            let val = self.parse_value_expr(0)?;
            let val_end = u32::try_from(self.pos).unwrap_or(val_start);
            self.skip_ts_postfix_assertions();
            let prop_end = u32::try_from(self.pos).unwrap_or(val_end);

            properties.push((
                key.clone(),
                ByteSpan {
                    start: prop_start,
                    end: prop_end,
                },
                ByteSpan {
                    start: val_start,
                    end: val_end,
                },
            ));
            map.insert(key, val);

            self.skip_ws_and_comments();
            if self.peek_byte() == Some(b',') {
                self.pos += 1;
            }
        }
    }

    fn parse_value_expr(&mut self, depth: usize) -> Result<Value, String> {
        if depth > 24 {
            return Err("Config expression nesting limit exceeded".to_string());
        }
        self.skip_ws_and_comments();
        if self.peek_byte() == Some(b'<') {
            self.skip_angle_bracket_type_assertion();
            self.skip_ws_and_comments();
        }
        let Some(b) = self.peek_byte() else {
            return Err("Unexpected end of config expression".to_string());
        };
        match b {
            b'{' => {
                let obj = self.parse_object()?;
                Ok(Value::Object(obj.map))
            }
            b'[' => self.parse_array(depth + 1),
            b'\'' | b'"' | b'`' => self.parse_string_literal().map(Value::String),
            b'(' => {
                self.pos += 1;
                let v = self.parse_value_expr(depth + 1)?;
                self.skip_ts_postfix_assertions();
                if self.peek_byte() == Some(b')') {
                    self.pos += 1;
                }
                Ok(v)
            }
            b'-' | b'0'..=b'9' => self.parse_number_literal(),
            _ => self.parse_ident_or_call_expr(depth),
        }
    }

    fn parse_ident_or_call_expr(&mut self, depth: usize) -> Result<Value, String> {
        let ident = self
            .parse_identifier()
            .ok_or_else(|| "Unsupported config expression".to_string())?;
        match ident.as_str() {
            "true" => Ok(Value::Bool(true)),
            "false" => Ok(Value::Bool(false)),
            "null" | "undefined" => Ok(Value::Null),
            _ => {
                self.skip_ws_and_comments();
                if self.peek_byte() == Some(b'<') {
                    self.skip_angle_bracket_type_assertion();
                    self.skip_ws_and_comments();
                }
                if self.peek_byte() == Some(b'(') {
                    self.pos += 1;
                    let v = self.parse_value_expr(depth + 1)?;
                    self.skip_ts_postfix_assertions();
                    if self.peek_byte() == Some(b')') {
                        self.pos += 1;
                    }
                    return Ok(v);
                }
                let target_pos = *self
                    .bindings
                    .get(&ident)
                    .ok_or_else(|| format!("Unresolved identifier {ident}"))?;
                let mut sub = ConfigCursor::with_pos(self.src, target_pos, self.bindings.clone());
                sub.parse_value_expr(depth + 1)
            }
        }
    }

    fn parse_array(&mut self, depth: usize) -> Result<Value, String> {
        self.pos += 1;
        let mut items = Vec::new();
        loop {
            self.skip_ws_and_comments();
            let Some(b) = self.peek_byte() else {
                return Err("Unterminated array literal".to_string());
            };
            if b == b']' {
                self.pos += 1;
                return Ok(Value::Array(items));
            }
            if b == b',' {
                self.pos += 1;
                continue;
            }
            let item = self.parse_value_expr(depth)?;
            self.skip_ts_postfix_assertions();
            items.push(item);
            self.skip_ws_and_comments();
            if self.peek_byte() == Some(b',') {
                self.pos += 1;
            }
        }
    }

    fn parse_string_literal(&mut self) -> Result<String, String> {
        let quote = self.peek_byte().ok_or("Expected string quote")?;
        self.pos += 1;
        let mut out = String::new();
        while let Some(&b) = self.bytes.get(self.pos) {
            if b == quote {
                self.pos += 1;
                return Ok(out);
            }
            if quote == b'`' && b == b'$' && self.bytes.get(self.pos + 1) == Some(&b'{') {
                return Err("Dynamic template literal interpolation in config".to_string());
            }
            if b == b'\\' {
                self.pos += 1;
                let Some(esc) = self.peek_byte() else {
                    break;
                };
                self.pos += 1;
                match esc {
                    b'n' => out.push('\n'),
                    b'r' => out.push('\r'),
                    b't' => out.push('\t'),
                    b'\\' => out.push('\\'),
                    b'\'' => out.push('\''),
                    b'"' => out.push('"'),
                    b'`' => out.push('`'),
                    other => out.push(other as char),
                }
                continue;
            }
            if let Some(ch) = self.src.get(self.pos..).and_then(|s| s.chars().next()) {
                out.push(ch);
                self.pos += ch.len_utf8();
            } else {
                self.pos += 1;
            }
        }
        Err("Unterminated string literal".to_string())
    }

    fn parse_number_literal(&mut self) -> Result<Value, String> {
        let start = self.pos;
        if self.peek_byte() == Some(b'-') {
            self.pos += 1;
            self.skip_ws_and_comments();
        }
        let num_start = self.pos;
        while let Some(b) = self.peek_byte() {
            if b.is_ascii_digit() || b == b'.' || b == b'_' {
                self.pos += 1;
            } else {
                break;
            }
        }
        if self.pos == num_start {
            return Err("Invalid numeric literal".to_string());
        }
        let raw = self
            .src
            .get(start..self.pos)
            .unwrap_or_default()
            .replace(['_', ' '], "");
        if let Ok(int_val) = raw.parse::<u64>() {
            return Ok(Value::Number(serde_json::Number::from(int_val)));
        }
        if let Ok(int_val) = raw.parse::<i64>() {
            return Ok(Value::Number(serde_json::Number::from(int_val)));
        }
        let parsed = raw
            .parse::<f64>()
            .map_err(|e| format!("Invalid number {raw}: {e}"))?;
        serde_json::Number::from_f64(parsed)
            .map(Value::Number)
            .ok_or_else(|| "Non-finite number in config".to_string())
    }

    fn skip_angle_bracket_type_assertion(&mut self) {
        if self.peek_byte() != Some(b'<') {
            return;
        }
        let mut depth = 0_i32;
        while let Some(b) = self.peek_byte() {
            self.pos += 1;
            if b == b'<' {
                depth += 1;
            } else if b == b'>' {
                depth -= 1;
                if depth <= 0 {
                    break;
                }
            }
        }
    }

    fn skip_ts_postfix_assertions(&mut self) {
        loop {
            self.skip_ws_and_comments();
            if self.peek_byte() == Some(b'!') {
                self.pos += 1;
                continue;
            }
            if self.consume_keyword("as") || self.consume_keyword("satisfies") {
                self.skip_ts_type_until_delimiter();
                continue;
            }
            break;
        }
    }

    fn skip_ts_type_until_delimiter(&mut self) {
        let mut depth = 0_i32;
        while self.pos < self.bytes.len() {
            self.skip_ws_and_comments();
            let Some(b) = self.peek_byte() else {
                break;
            };
            if depth == 0 && matches!(b, b',' | b'}' | b']' | b')' | b';') {
                break;
            }
            match b {
                b'<' | b'(' | b'[' | b'{' => {
                    depth += 1;
                    self.pos += 1;
                }
                b'>' | b')' | b']' | b'}' => {
                    depth = (depth - 1).max(0);
                    self.pos += 1;
                }
                _ => {
                    self.pos += 1;
                }
            }
        }
    }
}

const fn is_ident_start(b: u8) -> bool {
    b.is_ascii_alphabetic() || b == b'_' || b == b'$'
}

const fn is_ident_continue(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b == b'$'
}
