//! The rule-expression language v0 (R10 G4): the deterministic
//! reading of a class descriptor's rule references. A rule is a
//! boolean expression over the instance's twin-fact map — facts,
//! thresholds and membership — evaluated with fixed semantics and no
//! ambient state, so the same expression over the same facts reads
//! the same in every implementation.
//!
//! Grammar (recursive descent, no operator precedence surprises):
//!
//! ```text
//! expr       := or
//! or         := and  ( "or"  and  )*
//! and        := unary ( "and" unary )*
//! unary      := "not" unary | primary
//! primary    := "(" expr ")" | comparison
//! comparison := path op literal | path "in" "[" literal ( "," literal )* "]"
//! op         := "=" | "!=" | ">" | ">=" | "<" | "<="
//! literal    := number | "true" | "false" | quoted string
//! path       := segment ( "." segment )*
//! segment    := [A-Za-z0-9_]+
//! ```
//!
//! Evaluation semantics (clause 5's rule clause):
//! - a comparison over a decimal fact and a number literal orders
//!   them; the four ordering operators are decimal-only,
//! - `=` / `!=` read string facts against string literals and
//!   boolean facts against `true` / `false`,
//! - `in` reads membership: a string fact among string members, a
//!   decimal fact among number members,
//! - a fact absent at the compared path makes the comparison false
//!   (not an error) — a rule that requires a fact states it through
//!   the descriptor's `required` declaration,
//! - a fact of a different kind than the literal compares as false
//!   (the descriptor intake refuses such an expression against the
//!   declared kinds; the evaluation stays total regardless).
//!
//! The descriptor intake validates the expressions: each parses,
//! names only declared feature paths, and compares literals
//! compatible with the declared kinds. The instance intake evaluates
//! every referenced rule and names the failing rule and its
//! expression in the refusal.

use serde_json::Value;

// ---------------------------------------------------------------------------
// The expression tree
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
pub enum Expr {
    /// path, operator, literal
    Comparison(String, Op, Lit),
    /// path, members
    In(String, Vec<Lit>),
    And(Box<Expr>, Box<Expr>),
    Or(Box<Expr>, Box<Expr>),
    Not(Box<Expr>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op {
    Eq,
    Ne,
    Gt,
    Ge,
    Lt,
    Le,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Lit {
    Num(f64),
    Str(String),
    Bool(bool),
}

impl Lit {
    /// The literal's kind, named as the descriptor's kinds are.
    pub fn kind(&self) -> &'static str {
        match self {
            Lit::Num(_) => "decimal",
            Lit::Str(_) => "string",
            Lit::Bool(_) => "boolean",
        }
    }
}

// ---------------------------------------------------------------------------
// The parser
// ---------------------------------------------------------------------------

/// A parse failure: the offset and the reason (the refusal names it).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError {
    pub offset: usize,
    pub message: String,
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "at offset {}: {}", self.offset, self.message)
    }
}

struct Parser<'a> {
    chars: Vec<char>,
    offsets: Vec<usize>,
    pos: usize,
    _source: &'a str,
}

impl<'a> Parser<'a> {
    fn new(source: &'a str) -> Self {
        let chars: Vec<char> = source.chars().collect();
        let offsets: Vec<usize> = {
            let mut offsets = Vec::with_capacity(chars.len() + 1);
            let mut offset = 0;
            for c in &chars {
                offsets.push(offset);
                offset += c.len_utf8();
            }
            offsets.push(offset);
            offsets
        };
        Parser {
            chars,
            offsets,
            pos: 0,
            _source: source,
        }
    }

    fn offset(&self) -> usize {
        self.offsets[self.pos.min(self.offsets.len() - 1)]
    }

    fn err(&self, message: impl Into<String>) -> ParseError {
        ParseError {
            offset: self.offset(),
            message: message.into(),
        }
    }

    fn skip_spaces(&mut self) {
        while self.pos < self.chars.len() && self.chars[self.pos].is_whitespace() {
            self.pos += 1;
        }
    }

    fn peek_word(&self) -> String {
        let mut word = String::new();
        let mut i = self.pos;
        while i < self.chars.len()
            && (self.chars[i].is_alphanumeric() || self.chars[i] == '_' || self.chars[i] == '-')
        {
            word.push(self.chars[i]);
            i += 1;
        }
        word
    }

    /// A bare word followed by a boundary (space, `(`, end).
    fn take_word(&mut self) -> Option<String> {
        self.skip_spaces();
        let word = self.peek_word();
        if word.is_empty() {
            return None;
        }
        self.pos += word.chars().count();
        Some(word)
    }

    fn take_exact(&mut self, token: &str) -> bool {
        self.skip_spaces();
        let token_chars: Vec<char> = token.chars().collect();
        if self.chars[self.pos..].starts_with(&token_chars[..]) {
            self.pos += token_chars.len();
            return true;
        }
        false
    }

    fn parse_expr(&mut self) -> Result<Expr, ParseError> {
        self.parse_or()
    }

    fn parse_or(&mut self) -> Result<Expr, ParseError> {
        let mut left = self.parse_and()?;
        loop {
            self.skip_spaces();
            let save = self.pos;
            if self.take_word().as_deref() == Some("or") {
                let right = self.parse_and()?;
                left = Expr::Or(Box::new(left), Box::new(right));
            } else {
                self.pos = save;
                return Ok(left);
            }
        }
    }

    fn parse_and(&mut self) -> Result<Expr, ParseError> {
        let mut left = self.parse_unary()?;
        loop {
            self.skip_spaces();
            let save = self.pos;
            if self.take_word().as_deref() == Some("and") {
                let right = self.parse_unary()?;
                left = Expr::And(Box::new(left), Box::new(right));
            } else {
                self.pos = save;
                return Ok(left);
            }
        }
    }

    fn parse_unary(&mut self) -> Result<Expr, ParseError> {
        self.skip_spaces();
        let save = self.pos;
        if self.take_word().as_deref() == Some("not") {
            let inner = self.parse_unary()?;
            return Ok(Expr::Not(Box::new(inner)));
        }
        self.pos = save;
        self.parse_primary()
    }

    fn parse_primary(&mut self) -> Result<Expr, ParseError> {
        self.skip_spaces();
        if self.pos >= self.chars.len() {
            return Err(self.err("the expression ends where a term was expected"));
        }
        if self.chars[self.pos] == '(' {
            self.pos += 1;
            let inner = self.parse_expr()?;
            self.skip_spaces();
            if !self.take_exact(")") {
                return Err(self.err("expected `)`"));
            }
            return Ok(inner);
        }
        self.parse_comparison()
    }

    fn parse_path(&mut self) -> Result<String, ParseError> {
        self.skip_spaces();
        let mut path = String::new();
        loop {
            let word = self.peek_word();
            if word.is_empty() {
                if path.is_empty() {
                    return Err(self.err("expected a fact path"));
                }
                return Err(self.err("a fact path ends in a dot"));
            }
            path.push_str(&word);
            self.pos += word.chars().count();
            if self.pos < self.chars.len() && self.chars[self.pos] == '.' {
                path.push('.');
                self.pos += 1;
            } else {
                return Ok(path);
            }
        }
    }

    fn parse_comparison(&mut self) -> Result<Expr, ParseError> {
        let path = self.parse_path()?;
        self.skip_spaces();
        // The membership form.
        let save = self.pos;
        if self.take_word().as_deref() == Some("in") {
            self.skip_spaces();
            if !self.take_exact("[") {
                return Err(self.err("expected `[` after `in`"));
            }
            let mut members = Vec::new();
            loop {
                let literal = self.parse_literal()?;
                members.push(literal);
                self.skip_spaces();
                if self.take_exact(",") {
                    continue;
                }
                if self.take_exact("]") {
                    break;
                }
                return Err(self.err("expected `,` or `]` in the membership list"));
            }
            return Ok(Expr::In(path, members));
        }
        self.pos = save;
        let op = if self.take_exact("!=") {
            Op::Ne
        } else if self.take_exact(">=") {
            Op::Ge
        } else if self.take_exact("<=") {
            Op::Le
        } else if self.take_exact("=") {
            Op::Eq
        } else if self.take_exact(">") {
            Op::Gt
        } else if self.take_exact("<") {
            Op::Lt
        } else {
            return Err(self.err("expected a comparison operator"));
        };
        let literal = self.parse_literal()?;
        Ok(Expr::Comparison(path, op, literal))
    }

    fn parse_literal(&mut self) -> Result<Lit, ParseError> {
        self.skip_spaces();
        if self.pos >= self.chars.len() {
            return Err(self.err("the expression ends where a literal was expected"));
        }
        if self.chars[self.pos] == '"' || self.chars[self.pos] == '\'' {
            let quote = self.chars[self.pos];
            self.pos += 1;
            let mut text = String::new();
            while self.pos < self.chars.len() && self.chars[self.pos] != quote {
                text.push(self.chars[self.pos]);
                self.pos += 1;
            }
            if self.pos >= self.chars.len() {
                return Err(self.err("the string literal runs past the end"));
            }
            self.pos += 1;
            return Ok(Lit::Str(text));
        }
        let word = self.peek_word();
        match word.as_str() {
            "true" => {
                self.pos += word.chars().count();
                return Ok(Lit::Bool(true));
            }
            "false" => {
                self.pos += word.chars().count();
                return Ok(Lit::Bool(false));
            }
            _ => {}
        }
        // A number: digits with an optional fraction.
        let start = self.pos;
        let mut number = String::new();
        while self.pos < self.chars.len()
            && (self.chars[self.pos].is_ascii_digit() || self.chars[self.pos] == '.')
        {
            number.push(self.chars[self.pos]);
            self.pos += 1;
        }
        if !number.is_empty() && !number.starts_with('.') && number.ends_with('.') {
            return Err(self.err("a number cannot end in a dot"));
        }
        if let Ok(value) = number.parse::<f64>() {
            if !number.is_empty()
                && number
                    .chars()
                    .next()
                    .map(|c| c.is_ascii_digit())
                    .unwrap_or(false)
            {
                let _ = start;
                return Ok(Lit::Num(value));
            }
        }
        self.pos = start;
        Err(self.err("expected a literal (number, `true`, `false` or a quoted string)"))
    }
}

/// Parses a rule expression.
pub fn parse(source: &str) -> Result<Expr, ParseError> {
    let mut parser = Parser::new(source);
    let expr = parser.parse_expr()?;
    parser.skip_spaces();
    if parser.pos != parser.chars.len() {
        return Err(parser.err("unexpected trailing input"));
    }
    Ok(expr)
}

// ---------------------------------------------------------------------------
// The evaluator (total: absent facts and kind mismatches read false)
// ---------------------------------------------------------------------------

fn fact_as_number(fact: &Value) -> Option<f64> {
    fact.as_f64()
}

/// Evaluates the expression over the twin-fact map.
pub fn eval(expr: &Expr, facts: &Value) -> bool {
    match expr {
        Expr::Comparison(path, op, literal) => {
            let Some(fact) = facts.get(path) else {
                return false;
            };
            match (op, literal) {
                (Op::Eq, Lit::Str(wanted)) => fact.as_str() == Some(wanted.as_str()),
                (Op::Ne, Lit::Str(wanted)) => fact.as_str() != Some(wanted.as_str()),
                (Op::Eq, Lit::Bool(wanted)) => fact.as_bool() == Some(*wanted),
                (Op::Ne, Lit::Bool(wanted)) => fact.as_bool() != Some(*wanted),
                (_, Lit::Str(_)) | (_, Lit::Bool(_)) => false,
                (_, Lit::Num(wanted)) => {
                    let Some(value) = fact_as_number(fact) else {
                        return false;
                    };
                    match op {
                        Op::Eq => value == *wanted,
                        Op::Ne => value != *wanted,
                        Op::Gt => value > *wanted,
                        Op::Ge => value >= *wanted,
                        Op::Lt => value < *wanted,
                        Op::Le => value <= *wanted,
                    }
                }
            }
        }
        Expr::In(path, members) => {
            let Some(fact) = facts.get(path) else {
                return false;
            };
            match fact {
                Value::String(member) => members
                    .iter()
                    .any(|m| matches!(m, Lit::Str(wanted) if wanted == member)),
                Value::Number(_) => {
                    let Some(value) = fact_as_number(fact) else {
                        return false;
                    };
                    members
                        .iter()
                        .any(|m| matches!(m, Lit::Num(wanted) if *wanted == value))
                }
                _ => false,
            }
        }
        Expr::And(a, b) => eval(a, facts) && eval(b, facts),
        Expr::Or(a, b) => eval(a, facts) || eval(b, facts),
        Expr::Not(a) => !eval(a, facts),
    }
}

// ---------------------------------------------------------------------------
// The descriptor-side validation: paths declared, kinds compatible
// ---------------------------------------------------------------------------

use std::collections::BTreeSet;

/// A walk over every comparison the expression carries.
fn walk<'a>(expr: &'a Expr, visit: &mut impl FnMut(&'a Expr)) {
    visit(expr);
    match expr {
        Expr::And(a, b) | Expr::Or(a, b) => {
            walk(a, visit);
            walk(b, visit);
        }
        Expr::Not(a) => walk(a, visit),
        _ => {}
    }
}

/// The expression's descriptor-side errors against the declared
/// features: undeclared paths, ordering operators on non-decimal
/// facts, string/boolean literals against the wrong kinds, and `in`
/// over list or boolean features. Each error names the path.
pub fn descriptor_errors(
    expr: &Expr,
    features: &std::collections::BTreeMap<String, String>,
) -> Vec<String> {
    let mut errors: Vec<String> = Vec::new();
    let mut visit = |e: &Expr| {
        let (path, literal, membership) = match e {
            Expr::Comparison(path, _, literal) => (path, Some(literal), false),
            Expr::In(path, members) => (path, members.first(), true),
            _ => return,
        };
        let Some(kind) = features.get(path) else {
            errors.push(format!(
                "the expression names `{path}`, which the descriptor does not declare"
            ));
            return;
        };
        if membership {
            if kind != "string" && kind != "decimal" {
                errors.push(format!(
                    "the membership test on `{path}` reads a {kind} feature; `in` reads string and decimal facts"
                ));
            }
            return;
        }
        let Some(literal) = literal else { return };
        match (kind.as_str(), literal) {
            ("decimal", Lit::Num(_)) => {}
            ("string", Lit::Str(_)) => {}
            ("boolean", Lit::Bool(_)) => {}
            (declared, literal) => errors.push(format!(
                "the comparison on `{path}` pits a {declared} feature against a {} literal",
                literal.kind()
            )),
        }
        let ordering = matches!(e, Expr::Comparison(_, Op::Gt | Op::Ge | Op::Lt | Op::Le, _));
        if ordering && kind != "decimal" {
            errors.push(format!(
                "the ordering comparison on `{path}` reads a {kind} feature; the ordering operators are decimal-only"
            ));
        }
    };
    walk(expr, &mut visit);
    errors
}

/// The expression's fact paths (the declaration check).
pub fn paths(expr: &Expr) -> Vec<String> {
    let mut seen = BTreeSet::new();
    let mut visit = |e: &Expr| {
        let path = match e {
            Expr::Comparison(path, _, _) | Expr::In(path, _) => path,
            _ => return,
        };
        seen.insert(path.clone());
    };
    walk(expr, &mut visit);
    seen.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn facts(v: Value) -> Value {
        v
    }

    #[test]
    fn parses_the_threshold_form() {
        let expr = parse("tyre.pressure-bar >= 2.5").expect("parses");
        assert_eq!(
            expr,
            Expr::Comparison("tyre.pressure-bar".into(), Op::Ge, Lit::Num(2.5))
        );
    }

    #[test]
    fn parses_connectives_and_parentheses() {
        let expr = parse(
            "(tyre.season = \"winter\" or tyre.season = 'all-season') and not tyre.runflat = true",
        )
        .expect("parses");
        match expr {
            Expr::And(_, right) => assert!(matches!(*right, Expr::Not(_))),
            other => panic!("unexpected shape: {other:?}"),
        }
    }

    #[test]
    fn parses_the_membership_form() {
        let expr = parse("tyre.season in [\"winter\", \"summer\"]").expect("parses");
        assert_eq!(
            expr,
            Expr::In(
                "tyre.season".into(),
                vec![Lit::Str("winter".into()), Lit::Str("summer".into())]
            )
        );
    }

    #[test]
    fn a_malformed_expression_names_the_offset() {
        let err = parse("tyre.pressure-bar >").unwrap_err();
        assert!(err.message.contains("literal"));
        let err = parse("tyre.pressure = \"x\" and").unwrap_err();
        assert!(err.message.contains("ends"));
        let err = parse("tyre.pressure-bar >= 2.5 tyre.other = 1").unwrap_err();
        assert!(err.message.contains("trailing"));
    }

    #[test]
    fn evaluates_thresholds_over_facts() {
        let expr = parse("tyre.pressure-bar >= 2.5").unwrap();
        assert!(eval(&expr, &facts(json!({"tyre.pressure-bar": 2.7}))));
        assert!(!eval(&expr, &facts(json!({"tyre.pressure-bar": 2.1}))));
        // An absent fact reads false, not an error.
        assert!(!eval(&expr, &facts(json!({}))));
        // A wrong-kind fact reads false.
        assert!(!eval(&expr, &facts(json!({"tyre.pressure-bar": "high"}))));
    }

    #[test]
    fn evaluates_membership_and_equality() {
        let expr = parse("tyre.season in [\"winter\", \"summer\"]").unwrap();
        assert!(eval(&expr, &facts(json!({"tyre.season": "winter"}))));
        assert!(!eval(&expr, &facts(json!({"tyre.season": "competitive"}))));
        let eq = parse("tyre.runflat = true").unwrap();
        assert!(eval(&eq, &facts(json!({"tyre.runflat": true}))));
        assert!(!eval(&eq, &facts(json!({"tyre.runflat": false}))));
    }

    #[test]
    fn evaluation_is_deterministic_over_the_same_facts() {
        let expr = parse("a.count > 1 and (b.name = \"x\" or b.name = \"y\")").unwrap();
        let value = facts(json!({"a.count": 3, "b.name": "y"}));
        let first = eval(&expr, &value);
        for _ in 0..5 {
            assert_eq!(eval(&expr, &value), first);
        }
    }

    #[test]
    fn the_descriptor_side_names_undeclared_paths_and_kind_conflicts() {
        let mut features = std::collections::BTreeMap::new();
        features.insert("tyre.pressure-bar".to_string(), "decimal".to_string());
        features.insert("tyre.season".to_string(), "string".to_string());
        let declared_path = parse("tyre.pressure-bar > 2").unwrap();
        assert!(descriptor_errors(&declared_path, &features).is_empty());
        let undeclared = parse("tyre.depth > 2").unwrap();
        let errors = descriptor_errors(&undeclared, &features);
        assert!(errors.iter().any(|e| e.contains("tyre.depth")));
        let ordering_on_string = parse("tyre.season > \"winter\"").unwrap();
        let errors = descriptor_errors(&ordering_on_string, &features);
        assert!(errors.iter().any(|e| e.contains("decimal-only")));
        let string_vs_number = parse("tyre.season = 3").unwrap();
        let errors = descriptor_errors(&string_vs_number, &features);
        assert!(errors
            .iter()
            .any(|e| e.contains("string feature against a decimal literal")));
        let membership_on_boolean = parse("tyre.runflat in [\"x\"]").unwrap();
        let errors = descriptor_errors(&membership_on_boolean, &features);
        assert!(errors
            .iter()
            .any(|e| e.contains("does not declare") || e.contains("`in` reads")));
    }
}
