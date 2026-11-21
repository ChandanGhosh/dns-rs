//! Parser for the supported subset of the Unbound `.rpl` format.

use std::collections::HashMap;
use std::net::IpAddr;

use dns_proto::ResponseCode;

use crate::model::{
    Entry, EntryFlags, Range, RecordLine, ReplayConfig, ReplayFile, Reply, Scenario, Step, StepKind,
};

/// A syntax error in a replay file.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("{file}:{line}: {message}")]
pub struct ParseError {
    /// File or descriptive source name.
    pub file: String,
    /// One-based line number.
    pub line: usize,
    /// What went wrong.
    pub message: String,
}

type Result<T> = std::result::Result<T, ParseError>;

/// Default value substituted for `${timeout}`.
const DEFAULT_TIMEOUT: u64 = 10;
/// TTL used when an authoritative entry omits one.
const DEFAULT_TTL: u32 = 3600;

/// Parse one replay file.
///
/// # Errors
///
/// Returns [`ParseError`] for unbalanced blocks, malformed numbers or
/// addresses, unknown response codes, and short record lines.
pub fn parse(source: &str, text: &str) -> Result<ReplayFile> {
    let lines = preprocess(source, text)?;
    let mut cursor = Parser {
        source,
        lines,
        index: 0,
        variables: HashMap::from([("timeout".to_owned(), DEFAULT_TIMEOUT)]),
    };
    cursor.parse_file()
}

#[derive(Clone)]
struct Line {
    number: usize,
    tokens: Vec<String>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Section {
    Question,
    Answer,
    Authority,
    Additional,
}

impl Section {
    fn from_token(token: &str) -> Option<Self> {
        match token.to_ascii_uppercase().as_str() {
            "QUESTION" => Some(Self::Question),
            "ANSWER" => Some(Self::Answer),
            "AUTHORITY" => Some(Self::Authority),
            "ADDITIONAL" => Some(Self::Additional),
            _ => None,
        }
    }
}

struct Parser<'a> {
    source: &'a str,
    lines: Vec<Line>,
    index: usize,
    variables: HashMap<String, u64>,
}

impl Parser<'_> {
    fn error<T>(&self, line: usize, message: impl Into<String>) -> Result<T> {
        Err(ParseError {
            file: self.source.to_owned(),
            line,
            message: message.into(),
        })
    }

    fn peek(&self) -> Option<&Line> {
        self.lines.get(self.index)
    }

    fn next(&mut self) -> Option<Line> {
        let line = self.lines.get(self.index).cloned();
        if line.is_some() {
            self.index += 1;
        }
        line
    }

    fn parse_file(&mut self) -> Result<ReplayFile> {
        let mut config = ReplayConfig::default();
        let mut scenarios = Vec::new();
        while let Some(line) = self.peek() {
            let directive = line.tokens.first().map(String::as_str).unwrap_or_default();
            match directive {
                "CONFIG_END" => {
                    self.index += 1;
                }
                "COMMANDLINE" => {
                    config
                        .commandline
                        .extend(self.expand_tokens(&line.tokens[1..]));
                    config
                        .lines
                        .push(self.expand_tokens(&line.tokens).join(" "));
                    self.index += 1;
                }
                "AUTOTRUST_FILE" => {
                    config
                        .lines
                        .push(self.expand_tokens(&line.tokens).join(" "));
                    self.index += 1;
                    self.parse_autotrust(&mut config)?;
                }
                "TEMPFILE_NAME" | "TEMPFILE_CONTENTS" => {
                    config
                        .lines
                        .push(self.expand_tokens(&line.tokens).join(" "));
                    self.parse_tempfile(&mut config)?;
                }
                "SCENARIO_BEGIN" => scenarios.push(self.parse_scenario()?),
                _ => {
                    config
                        .lines
                        .push(self.expand_tokens(&line.tokens).join(" "));
                    self.index += 1;
                }
            }
        }
        if scenarios.is_empty() {
            return self.error(1, "file contains no scenarios");
        }
        Ok(ReplayFile {
            source: self.source.to_owned(),
            config,
            scenarios,
        })
    }

    fn parse_autotrust(&mut self, config: &mut ReplayConfig) -> Result<()> {
        loop {
            let line = self.next().ok_or_else(|| ParseError {
                file: self.source.to_owned(),
                line: self.lines.len() + 1,
                message: "AUTOTRUST_FILE has no AUTOTRUST_END".to_owned(),
            })?;
            match line.tokens.first().map(String::as_str) {
                Some("AUTOTRUST_END") => return Ok(()),
                _ => config.autotrust.extend(self.expand_tokens(&line.tokens)),
            }
        }
    }

    fn parse_tempfile(&mut self, config: &mut ReplayConfig) -> Result<()> {
        let header = self.peek().expect("peek");
        let name = self.expand_tokens(&header.tokens[1..]).join(" ");
        self.index += 1;
        let mut contents = Vec::new();
        loop {
            let line = self.next().ok_or_else(|| ParseError {
                file: self.source.to_owned(),
                line: self.lines.len() + 1,
                message: "TEMPFILE_CONTENTS has no TEMPFILE_END".to_owned(),
            })?;
            match line.tokens.first().map(String::as_str) {
                Some("TEMPFILE_END") => break,
                _ => contents.push(self.expand_tokens(&line.tokens).join(" ")),
            }
        }
        config.tempfiles.insert(name, contents.join("\n"));
        Ok(())
    }

    fn parse_scenario(&mut self) -> Result<Scenario> {
        let header = self.next().expect("peek");
        let name = self.expand_tokens(&header.tokens[1..]).join(" ");
        let mut ranges = Vec::new();
        let mut steps = Vec::new();
        loop {
            let line = self.peek().ok_or_else(|| ParseError {
                file: self.source.to_owned(),
                line: self.lines.len() + 1,
                message: format!("scenario {name:?} has no SCENARIO_END"),
            })?;
            match line.tokens.first().map(String::as_str) {
                Some("SCENARIO_END") => {
                    self.index += 1;
                    break;
                }
                Some("RANGE_BEGIN") => ranges.push(self.parse_range()?),
                Some("STEP") => steps.push(self.parse_step()?),
                Some(other) => {
                    return self.error(
                        line.number,
                        format!("unexpected scenario directive {other:?}"),
                    );
                }
                None => unreachable!("preprocess removes empty lines"),
            }
        }
        Ok(Scenario {
            name,
            ranges,
            steps,
        })
    }

    fn parse_range(&mut self) -> Result<Range> {
        let header = self.next().expect("peek");
        let tokens = self.expand_tokens(&header.tokens[1..]);
        let start = parse_number(&tokens, 0, header.number, self.source)?;
        let end = parse_number(&tokens, 1, header.number, self.source)?;
        let mut range = Range {
            start,
            end,
            address: None,
            entries: Vec::new(),
        };
        loop {
            let line = self.peek().ok_or_else(|| ParseError {
                file: self.source.to_owned(),
                line: self.lines.len() + 1,
                message: "RANGE_BEGIN has no RANGE_END".to_owned(),
            })?;
            match line.tokens.first().map(String::as_str) {
                Some("RANGE_END") => {
                    self.index += 1;
                    break;
                }
                Some("ADDRESS") => {
                    let value = self.expand_tokens(&line.tokens[1..]).join(" ");
                    range.address = Some(parse_address(&value, line.number, self.source)?);
                    self.index += 1;
                }
                Some("ENTRY_BEGIN") => range.entries.push(self.parse_entry()?),
                Some(other) => {
                    return self
                        .error(line.number, format!("unexpected range directive {other:?}"));
                }
                None => unreachable!(),
            }
        }
        Ok(range)
    }

    fn parse_step(&mut self) -> Result<Step> {
        let header = self.next().expect("peek");
        let raw = &header.tokens[1..];
        let tokens = self.expand_tokens(raw);
        let time = parse_number(&tokens, 0, header.number, self.source)?;
        self.variables.insert("time".to_owned(), time);
        let event = tokens.get(1).cloned().unwrap_or_default();
        let kind = match event.as_str() {
            "QUERY" => StepKind::Query,
            "CHECK_ANSWER" => StepKind::CheckAnswer,
            "CHECK_OUT_QUERY" => StepKind::CheckOutQuery,
            "TIME_PASSES" => {
                let expression = self.expand(&raw.get(3..).unwrap_or_default().join(" "));
                let seconds = evaluate(&expression, &self.variables).ok_or_else(|| ParseError {
                    file: self.source.to_owned(),
                    line: header.number,
                    message: format!("invalid TIME_PASSES value {expression:?}"),
                })?;
                StepKind::TimePasses(seconds)
            }
            "REPLY" => StepKind::Reply,
            "TIMEOUT" => StepKind::Timeout,
            "TRAFFIC" => StepKind::Traffic,
            "CHECK_AUTOTRUST" => StepKind::CheckAutotrust,
            "CHECK_TEMPFILE" => StepKind::CheckTempfile,
            "INFRA_RTT" => StepKind::InfraRtt,
            "FLUSH_MESSAGE" => StepKind::FlushMessage,
            "EXPIRE_MESSAGE" => StepKind::ExpireMessage,
            "ERROR" => StepKind::Error,
            other => StepKind::Unsupported(other.to_owned()),
        };
        let address = tokens
            .iter()
            .position(|token| token == "ADDRESS")
            .and_then(|position| tokens.get(position + 1))
            .map(|value| parse_address(value, header.number, self.source))
            .transpose()?;
        let file = tokens
            .get(2)
            .cloned()
            .filter(|_| matches!(kind, StepKind::CheckAutotrust | StepKind::CheckTempfile));
        let entry = if self.peek().is_some_and(|line| {
            line.tokens
                .first()
                .is_some_and(|token| token == "ENTRY_BEGIN")
        }) {
            Some(self.parse_entry()?)
        } else {
            None
        };
        if self.peek().is_some_and(|line| {
            line.tokens
                .first()
                .is_some_and(|token| token == "FILE_BEGIN")
        }) {
            self.parse_file_block()?;
        }
        Ok(Step {
            time,
            kind,
            address,
            entry,
            file,
        })
    }

    fn parse_entry(&mut self) -> Result<Entry> {
        self.index += 1;
        let mut entry = Entry::default();
        let mut section = None;
        loop {
            let line = self.next().ok_or_else(|| ParseError {
                file: self.source.to_owned(),
                line: self.lines.len() + 1,
                message: "ENTRY_BEGIN has no ENTRY_END".to_owned(),
            })?;
            let tokens = self.expand_tokens(&line.tokens);
            match tokens.first().map(String::as_str) {
                Some("ENTRY_END") => break,
                Some("MATCH") => entry.matches.extend(tokens[1..].iter().cloned()),
                Some("ADJUST") => entry.adjusts.extend(tokens[1..].iter().cloned()),
                Some("REPLY") => entry
                    .replies
                    .push(self.parse_reply(&tokens[1..], line.number)?),
                Some("EXTRA_PACKET") => section = None,
                Some("SECTION") => {
                    let name = tokens.get(1).ok_or_else(|| ParseError {
                        file: self.source.to_owned(),
                        line: line.number,
                        message: "SECTION has no name".to_owned(),
                    })?;
                    let parsed = Section::from_token(name).ok_or_else(|| ParseError {
                        file: self.source.to_owned(),
                        line: line.number,
                        message: format!("unknown section {name:?}"),
                    })?;
                    section = Some(parsed);
                    if entry.replies.is_empty() {
                        entry.replies.push(Reply::default());
                    }
                }
                Some(_) => {
                    let Some(section) = section else {
                        return self
                            .error(line.number, format!("record outside a section: {tokens:?}"));
                    };
                    let record = self.parse_record(&tokens, line.number)?;
                    let reply = entry.replies.last_mut().ok_or_else(|| ParseError {
                        file: self.source.to_owned(),
                        line: line.number,
                        message: "section before REPLY".to_owned(),
                    })?;
                    match section {
                        Section::Question => reply.question.push(record),
                        Section::Answer => reply.answer.push(record),
                        Section::Authority => reply.authority.push(record),
                        Section::Additional => reply.additional.push(record),
                    }
                }
                None => unreachable!(),
            }
        }
        if entry.replies.is_empty() {
            entry.replies.push(Reply::default());
        }
        Ok(entry)
    }

    fn parse_reply(&self, tokens: &[String], line: usize) -> Result<Reply> {
        let mut reply = Reply::default();
        for token in tokens {
            if let Some(rcode) = parse_rcode(token) {
                reply.rcode = rcode;
            } else if is_known_opcode(token) {
                reply.op_code = token.clone();
            } else if let Some(flag) = parse_flag(token) {
                set_flag(&mut reply.flags, flag);
            } else {
                return self.error(line, format!("unknown REPLY token {token:?}"));
            }
        }
        Ok(reply)
    }

    fn parse_record(&self, tokens: &[String], line: usize) -> Result<RecordLine> {
        if tokens.len() < 3 {
            return self.error(line, "short record line");
        }
        let ttl = tokens[1].parse::<u32>().ok();
        let offset = usize::from(ttl.is_some());
        if tokens.len() < offset + 3 {
            return self.error(line, "short record line");
        }
        Ok(RecordLine {
            owner: tokens[0].clone(),
            ttl: ttl.or(Some(DEFAULT_TTL)),
            class: tokens[offset + 1].clone(),
            rtype: tokens[offset + 2].clone(),
            rdata: tokens[offset + 3..].to_vec(),
        })
    }

    fn parse_file_block(&mut self) -> Result<()> {
        loop {
            let line = self.next().ok_or_else(|| ParseError {
                file: self.source.to_owned(),
                line: self.lines.len() + 1,
                message: "FILE_BEGIN has no FILE_END".to_owned(),
            })?;
            if line.tokens.first().is_some_and(|token| token == "FILE_END") {
                return Ok(());
            }
        }
    }

    fn expand_tokens(&self, tokens: &[String]) -> Vec<String> {
        tokens.iter().map(|token| self.expand(token)).collect()
    }

    fn expand(&self, token: &str) -> String {
        let mut output = String::with_capacity(token.len());
        let mut rest = token;
        while let Some(start) = rest.find('$') {
            output.push_str(&rest[..start]);
            let after = &rest[start + 1..];
            if let Some(expr) = after.strip_prefix('{') {
                let Some(end) = expr.find('}') else {
                    output.push('$');
                    rest = after;
                    continue;
                };
                if let Some(value) = evaluate(&expr[..end], &self.variables) {
                    output.push_str(&value.to_string());
                } else {
                    output.push_str(&rest[start..start + end + 3]);
                }
                rest = &expr[end + 1..];
            } else {
                let name_len = after
                    .find(|c: char| !c.is_ascii_alphanumeric() && c != '_')
                    .unwrap_or(after.len());
                if let Some(value) = self.variables.get(&after[..name_len]) {
                    output.push_str(&value.to_string());
                } else {
                    output.push_str(&rest[start..start + name_len + 1]);
                }
                rest = &after[name_len..];
            }
        }
        output.push_str(rest);
        output
    }
}

fn preprocess(source: &str, text: &str) -> Result<Vec<Line>> {
    let mut lines = Vec::new();
    for (number, raw) in text.lines().enumerate() {
        let tokens = tokenize(raw);
        if tokens.is_empty() {
            continue;
        }
        lines.push(Line {
            number: number + 1,
            tokens,
        });
    }
    if lines.is_empty() {
        return Err(ParseError {
            file: source.to_owned(),
            line: 1,
            message: "empty replay file".to_owned(),
        });
    }
    Ok(lines)
}

fn tokenize(raw: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut quoted = false;
    for ch in raw.chars() {
        match ch {
            ';' if !quoted => break,
            '"' => {
                quoted = !quoted;
                current.push(ch);
            }
            c if c.is_whitespace() && !quoted => {
                if !current.is_empty() {
                    tokens.push(std::mem::take(&mut current));
                }
            }
            _ => current.push(ch),
        }
    }
    if !current.is_empty() {
        tokens.push(current);
    }
    tokens
}

fn parse_number(tokens: &[String], index: usize, line: usize, source: &str) -> Result<u64> {
    tokens
        .get(index)
        .ok_or_else(|| ParseError {
            file: source.to_owned(),
            line,
            message: format!("missing argument {index}"),
        })?
        .parse()
        .map_err(|_| ParseError {
            file: source.to_owned(),
            line,
            message: format!("invalid number {:?}", tokens[index]),
        })
}

fn parse_address(value: &str, line: usize, source: &str) -> Result<IpAddr> {
    value.parse().map_err(|_| ParseError {
        file: source.to_owned(),
        line,
        message: format!("invalid IP address {value:?}"),
    })
}

fn parse_rcode(token: &str) -> Option<ResponseCode> {
    let code = match token.to_ascii_uppercase().as_str() {
        "NOERROR" => 0,
        "FORMERR" => 1,
        "SERVFAIL" => 2,
        "NXDOMAIN" => 3,
        "NOTIMP" | "NOTIMPL" => 4,
        "REFUSED" => 5,
        "YXDOMAIN" => 6,
        "YXRRSET" => 7,
        "NXRRSET" => 8,
        "NOTAUTH" => 9,
        "NOTZONE" => 10,
        "BADVERS" | "BADVERSION" => 11,
        _ => return None,
    };
    Some(ResponseCode::from_low(code))
}

fn is_known_opcode(token: &str) -> bool {
    matches!(
        token.to_ascii_uppercase().as_str(),
        "QUERY" | "IQUERY" | "STATUS" | "NOTIFY" | "UPDATE"
    )
}

#[derive(Clone, Copy)]
enum Flag {
    Qr,
    Aa,
    Tc,
    Rd,
    Ra,
    Ad,
    Cd,
}

fn parse_flag(token: &str) -> Option<Flag> {
    match token.to_ascii_uppercase().as_str() {
        "QR" => Some(Flag::Qr),
        "AA" => Some(Flag::Aa),
        "TC" => Some(Flag::Tc),
        "RD" => Some(Flag::Rd),
        "RA" => Some(Flag::Ra),
        "AD" => Some(Flag::Ad),
        "CD" => Some(Flag::Cd),
        _ => None,
    }
}

fn set_flag(flags: &mut EntryFlags, flag: Flag) {
    match flag {
        Flag::Qr => flags.qr = true,
        Flag::Aa => flags.aa = true,
        Flag::Tc => flags.tc = true,
        Flag::Rd => flags.rd = true,
        Flag::Ra => flags.ra = true,
        Flag::Ad => flags.ad = true,
        Flag::Cd => flags.cd = true,
    }
}

/// Evaluate a small integer expression with `+ - * /` and parentheses.
fn evaluate(expression: &str, variables: &HashMap<String, u64>) -> Option<u64> {
    let tokens = tokenize_expression(expression)?;
    let mut parser = ExprParser {
        tokens,
        index: 0,
        variables,
    };
    let value = parser.sum()?;
    (parser.index == parser.tokens.len()).then_some(value)
}

#[derive(Clone)]
enum Token {
    Number(u64),
    Name(String),
    Op(char),
}

fn tokenize_expression(expression: &str) -> Option<Vec<Token>> {
    let mut tokens = Vec::new();
    let mut chars = expression.chars().peekable();
    while let Some(ch) = chars.next() {
        match ch {
            c if c.is_ascii_whitespace() => {}
            c if c.is_ascii_digit() => {
                let mut number = c.to_digit(10)? as u64;
                while let Some(next) = chars.peek().and_then(|c| c.to_digit(10)) {
                    number = number.checked_mul(10)?.checked_add(u64::from(next))?;
                    chars.next();
                }
                tokens.push(Token::Number(number));
            }
            c if c.is_ascii_alphabetic() || c == '_' => {
                let mut name = String::from(c);
                while let Some(next) = chars.peek().copied() {
                    if next.is_ascii_alphanumeric() || next == '_' {
                        name.push(next);
                        chars.next();
                    } else {
                        break;
                    }
                }
                tokens.push(Token::Name(name));
            }
            '+' | '-' | '*' | '/' | '(' | ')' => tokens.push(Token::Op(ch)),
            _ => return None,
        }
    }
    Some(tokens)
}

struct ExprParser<'a> {
    tokens: Vec<Token>,
    index: usize,
    variables: &'a HashMap<String, u64>,
}

impl ExprParser<'_> {
    fn sum(&mut self) -> Option<u64> {
        let mut value = self.product()?;
        loop {
            match self.tokens.get(self.index) {
                Some(Token::Op('+')) => {
                    self.index += 1;
                    value = value.checked_add(self.product()?)?;
                }
                Some(Token::Op('-')) => {
                    self.index += 1;
                    value = value.checked_sub(self.product()?)?;
                }
                _ => return Some(value),
            }
        }
    }

    fn product(&mut self) -> Option<u64> {
        let mut value = self.atom()?;
        loop {
            match self.tokens.get(self.index) {
                Some(Token::Op('*')) => {
                    self.index += 1;
                    value = value.checked_mul(self.atom()?)?;
                }
                Some(Token::Op('/')) => {
                    self.index += 1;
                    value = value.checked_div(self.atom()?)?;
                }
                _ => return Some(value),
            }
        }
    }

    fn atom(&mut self) -> Option<u64> {
        let token = self.tokens.get(self.index)?.clone();
        self.index += 1;
        match token {
            Token::Number(value) => Some(value),
            Token::Name(name) => self.variables.get(&name).copied(),
            Token::Op('(') => {
                let value = self.sum()?;
                if matches!(self.tokens.get(self.index), Some(Token::Op(')'))) {
                    self.index += 1;
                    Some(value)
                } else {
                    None
                }
            }
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use dns_proto::ResponseCode;

    use super::{evaluate, parse, parse_rcode};
    use crate::model::{Step, StepKind};

    const SAMPLE: &str = r#"
        ; config options
        server:
            do-daemonize: no

        CONFIG_END
        SCENARIO_BEGIN Basic referral
        RANGE_BEGIN 0 100
            ADDRESS 193.0.14.129
            ENTRY_BEGIN
                MATCH opcode subdomain
                ADJUST copy_id copy_query
                REPLY QR NOERROR
                SECTION QUESTION
                com. IN NS
                SECTION AUTHORITY
                com. IN NS a.gtld-servers.net.
                SECTION ADDITIONAL
                a.gtld-servers.net. IN A 192.5.6.30
            ENTRY_END
        RANGE_END
        STEP 1 QUERY
        ENTRY_BEGIN
        SECTION QUESTION
        www.example.com. IN A
        ENTRY_END
        STEP 2 TIME_PASSES ELAPSE ${time - 1}
        STEP 3 CHECK_ANSWER
        ENTRY_BEGIN
        MATCH all
        REPLY QR AA NOERROR
        SECTION QUESTION
        www.example.com. IN A
        SECTION ANSWER
        www.example.com. 60 IN A 192.0.2.10
        ENTRY_END
        SCENARIO_END
    "#;

    #[test]
    fn parses_unbound_style_sections() {
        let file = parse("sample.rpl", SAMPLE).expect("parse");
        assert_eq!(file.config.lines, vec!["server:", "do-daemonize: no"]);
        assert_eq!(file.scenarios.len(), 1);
        let scenario = &file.scenarios[0];
        assert_eq!(scenario.name, "Basic referral");
        assert_eq!(scenario.ranges.len(), 1);
        let entry = &scenario.ranges[0].entries[0];
        assert_eq!(entry.matches, vec!["opcode", "subdomain"]);
        assert_eq!(entry.adjusts, vec!["copy_id", "copy_query"]);
        let reply = entry.first_reply().expect("reply");
        assert_eq!(reply.rcode, ResponseCode::NoError);
        assert!(reply.flags.qr);
        assert_eq!(reply.authority.len(), 1);
        assert_eq!(reply.additional[0].rdata, vec!["192.5.6.30"]);
        assert_eq!(scenario.steps.len(), 3);
        assert!(matches!(scenario.steps[1].kind, StepKind::TimePasses(1)));
        let answer: &Step = &scenario.steps[2];
        assert_eq!(
            answer
                .entry
                .as_ref()
                .expect("entry")
                .first_reply()
                .expect("reply")
                .answer
                .len(),
            1
        );
    }

    #[test]
    fn rejects_unbalanced_blocks() {
        let error = parse("broken.rpl", "SCENARIO_BEGIN broken\n").expect_err("must fail");
        assert_eq!(error.file, "broken.rpl");
        assert!(error.message.contains("SCENARIO_END"));
    }

    #[test]
    fn rejects_unknown_numeric_macros() {
        let text = "SCENARIO_BEGIN broken\nRANGE_BEGIN ${range 1 2 3} 100\nSCENARIO_END\n";
        let error = parse("macro.rpl", text).expect_err("must fail");
        assert!(error.message.contains("invalid number"));
    }

    #[test]
    fn expands_macros_and_maps_response_codes() {
        let variables = [("time".to_owned(), 7)].into_iter().collect();
        assert_eq!(evaluate("(time + 3) * 2", &variables), Some(20));
        assert_eq!(evaluate("${range 1 2 3}", &variables), None);
        assert_eq!(parse_rcode("NOTIMPL"), Some(ResponseCode::NotImp));
    }
}
