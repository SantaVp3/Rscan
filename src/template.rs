//! Nuclei风格的模板数据结构定义
//! 
//! 本模块定义了用于Web扫描的模板结构，支持Nuclei风格的YAML模板格式。
//! 包含了模板的基本信息、请求定义、匹配器和提取器等核心组件。

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use crate::nuclei_dsl::{DslValue, WorkflowContext};
use crate::Result;

/// 模板严重性等级
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// 信息级别
    Info,
    /// 低危
    Low,
    /// 中危
    Medium,
    /// 高危
    High,
    /// 严重
    Critical,
}

/// 作者信息类型（支持字符串或字符串数组）
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum AuthorInfo {
    /// 单个作者（字符串）
    Single(String),
    /// 多个作者（字符串数组）
    Multiple(Vec<String>),
}

impl Default for AuthorInfo {
    fn default() -> Self {
        AuthorInfo::Single("unknown".to_string())
    }
}

impl std::fmt::Display for AuthorInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthorInfo::Single(author) => write!(f, "{}", author),
            AuthorInfo::Multiple(authors) => write!(f, "{}", authors.join(", ")),
        }
    }
}

impl std::fmt::Display for ReferenceInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReferenceInfo::Single(reference) => write!(f, "{}", reference),
            ReferenceInfo::Multiple(references) => write!(f, "{}", references.join(", ")),
        }
    }
}

/// 参考链接类型（支持字符串或字符串数组）
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ReferenceInfo {
    /// 单个链接（字符串）
    Single(String),
    /// 多个链接（字符串数组）
    Multiple(Vec<String>),
}

/// 标签信息类型（支持字符串或字符串数组）
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum TagsInfo {
    /// 单个标签（字符串）
    Single(String),
    /// 多个标签（字符串数组）
    Multiple(Vec<String>),
}

/// 模板信息块
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemplateInfo {
    /// 模板名称
    pub name: String,
    /// 作者信息（支持字符串或字符串数组）
    #[serde(default)]
    pub author: Option<AuthorInfo>,
    /// 严重性等级
    #[serde(default)]
    pub severity: Option<Severity>,
    /// 描述信息
    pub description: Option<String>,
    /// 参考链接（支持字符串或字符串数组）
    pub reference: Option<ReferenceInfo>,
    /// 标签列表（支持字符串或字符串数组）
    pub tags: Option<TagsInfo>,
    /// 分类信息
    pub classification: Option<Classification>,
    /// 修复建议
    pub remediation: Option<String>,
    /// 其他元数据
    #[serde(flatten)]
    pub metadata: HashMap<String, serde_json::Value>,
}

/// 分类信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Classification {
    /// CVE编号
    #[serde(rename = "cve-id")]
    pub cve_id: Option<String>,
    /// CWE编号
    #[serde(rename = "cwe-id")]
    pub cwe_id: Option<String>,
    /// CVSS评分
    #[serde(rename = "cvss-metrics")]
    pub cvss_metrics: Option<String>,
    /// CVSS评分值
    #[serde(rename = "cvss-score")]
    pub cvss_score: Option<f32>,
}

/// 路径信息类型（支持字符串或字符串数组）
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum PathInfo {
    /// 单个路径（字符串）
    Single(String),
    /// 多个路径（字符串数组）
    Multiple(Vec<String>),
}

/// HTTP请求定义
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpRequest {
    /// HTTP方法
    pub method: Option<String>,
    /// 请求路径（支持字符串或字符串数组）
    pub path: Option<PathInfo>,
    /// 请求头
    pub headers: Option<HashMap<String, String>>,
    /// 请求体
    pub body: Option<String>,
    /// 原始请求
    pub raw: Option<Vec<String>>,
    /// Cookie重用
    #[serde(rename = "cookie-reuse")]
    pub cookie_reuse: Option<bool>,
    /// 重定向跟随
    #[serde(rename = "redirects")]
    pub redirects: Option<bool>,
    /// 最大重定向次数
    #[serde(rename = "max-redirects")]
    pub max_redirects: Option<u32>,
    /// 管道请求
    pub pipeline: Option<bool>,
    /// 不安全的HTTP
    pub unsafe_http: Option<bool>,
    /// 竞争条件
    pub race: Option<bool>,
    /// 竞争条件数量
    #[serde(rename = "race-count")]
    pub race_count: Option<u32>,
    /// 请求条件
    #[serde(rename = "req-condition")]
    pub req_condition: Option<bool>,
    /// 停止条件
    #[serde(rename = "stop-at-first-match")]
    pub stop_at_first_match: Option<bool>,
    /// 匹配器
    pub matchers: Option<Vec<Matcher>>,
    /// 匹配器条件
    #[serde(rename = "matchers-condition")]
    pub matchers_condition: Option<MatchersCondition>,
    /// 提取器
    pub extractors: Option<Vec<Extractor>>,
}

/// 匹配器条件定义
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum MatchersCondition {
    /// 简单条件（字符串形式）
    Simple(String),
    /// 复杂条件（结构化形式）
    Complex(ComplexCondition),
}

/// 复杂匹配器条件
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplexCondition {
    /// 条件类型
    #[serde(rename = "type")]
    pub condition_type: String,
    /// 子条件列表
    pub conditions: Vec<MatchersCondition>,
}

impl Default for MatchersCondition {
    fn default() -> Self {
        MatchersCondition::Simple("and".to_string())
    }
}

/// 匹配器类型
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum MatcherType {
    /// 状态码匹配
    Status {
        /// 匹配器类型
        #[serde(rename = "type")]
        matcher_type: String,
        /// 状态码列表
        status: Vec<u16>,
    },
    /// 大小匹配
    Size {
        /// 匹配器类型
        #[serde(rename = "type")]
        matcher_type: String,
        /// 大小值
        size: Vec<u64>,
    },
    /// 单词匹配
    Word {
        /// 匹配器类型
        #[serde(rename = "type")]
        matcher_type: String,
        /// 单词列表
        words: Vec<String>,
        /// 是否区分大小写
        #[serde(rename = "case-insensitive")]
        case_insensitive: Option<bool>,
        /// 匹配条件
        condition: Option<String>,
    },
    /// 正则表达式匹配
    Regex {
        /// 匹配器类型
        #[serde(rename = "type")]
        matcher_type: String,
        /// 正则表达式列表
        regex: Vec<String>,
    },
    /// 二进制匹配
    Binary {
        /// 匹配器类型
        #[serde(rename = "type")]
        matcher_type: String,
        /// 二进制数据（十六进制编码）
        binary: Vec<String>,
    },
    /// DSL表达式匹配
    Dsl {
        /// 匹配器类型
        #[serde(rename = "type")]
        matcher_type: String,
        /// DSL表达式列表
        dsl: Vec<String>,
    },
}

/// 匹配器定义
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Matcher {
    /// 匹配器名称
    pub name: Option<String>,
    /// 匹配器类型
    #[serde(rename = "type")]
    pub matcher_type: String,
    /// 单词列表（用于word类型匹配器）
    pub words: Option<Vec<String>>,
    /// 状态码列表（用于status类型匹配器）
    pub status: Option<Vec<u16>>,
    /// 正则表达式列表（用于regex类型匹配器）
    pub regex: Option<Vec<String>>,
    /// DSL表达式列表（用于dsl类型匹配器）
    pub dsl: Option<Vec<String>>,
    /// 二进制数据列表（用于binary类型匹配器）
    pub binary: Option<Vec<String>>,
    /// 大小值列表（用于size类型匹配器）
    pub size: Option<Vec<u64>>,
    /// 匹配部分
    pub part: Option<String>,
    /// 编码方式
    pub encoding: Option<String>,
    /// 是否为负匹配
    pub negative: Option<bool>,
    /// 条件（and/or）
    pub condition: Option<String>,
    /// 是否区分大小写
    #[serde(rename = "case-insensitive")]
    pub case_insensitive: Option<bool>,
}

/// 提取器类型
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum ExtractorType {
    /// 正则表达式提取
    Regex {
        /// 正则表达式列表
        regex: Vec<String>,
        /// 分组索引
        group: Option<u32>,
    },
    /// 键值对提取
    Kval {
        /// 键值对列表
        kval: Vec<String>,
    },
    /// JSON提取
    Json {
        /// JSON路径列表
        json: Vec<String>,
    },
    /// XPath提取
    Xpath {
        /// XPath表达式列表
        xpath: Vec<String>,
    },
    /// DSL表达式提取
    Dsl {
        /// DSL表达式列表
        dsl: Vec<String>,
    },
}

/// 提取器定义
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Extractor {
    /// 提取器名称（可选）
    pub name: Option<String>,
    /// 提取器类型
    #[serde(rename = "type")]
    pub extractor_type: Option<String>,
    /// 正则表达式列表（用于regex类型提取器）
    pub regex: Option<Vec<String>>,
    /// 键值对列表（用于kval类型提取器）
    pub kval: Option<Vec<String>>,
    /// JSON路径列表（用于json类型提取器）
    pub json: Option<Vec<String>>,
    /// XPath表达式列表（用于xpath类型提取器）
    pub xpath: Option<Vec<String>>,
    /// DSL表达式列表（用于dsl类型提取器）
    pub dsl: Option<Vec<String>>,
    /// 分组索引
    pub group: Option<u32>,
    /// 提取部分
    pub part: Option<String>,
    /// 是否为内部提取器
    pub internal: Option<bool>,
    /// 是否区分大小写
    #[serde(rename = "case-insensitive")]
    pub case_insensitive: Option<bool>,
}

/// 工作流步骤
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowStep {
    /// 模板路径
    pub template: Option<String>,
    /// 标签选择器
    pub tags: Option<String>,
    /// 子模板
    pub subtemplates: Option<Vec<WorkflowStep>>,
    /// 匹配器名称（用于条件执行）
    pub matchers: Option<Vec<String>>,
}

/// 规则定义（用于某些nuclei模板格式）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    /// 请求定义
    pub request: Option<HttpRequest>,
    /// 表达式
    pub expression: Option<String>,
}

/// 完整的模板定义
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Template {
    /// 模板唯一标识符（可选，如果缺失则使用文件名）
    pub id: Option<String>,
    /// 模板信息（可选）
    pub info: Option<TemplateInfo>,
    /// HTTP请求列表（支持两种字段名）
    pub http: Option<Vec<HttpRequest>>,
    /// 请求列表（兼容性字段）
    pub requests: Option<Vec<HttpRequest>>,
    /// 规则定义（另一种模板格式）
    pub rules: Option<HashMap<String, Rule>>,
    /// DNS请求列表
    pub dns: Option<Vec<DnsRequest>>,
    /// 网络请求列表
    pub network: Option<Vec<NetworkRequest>>,
    /// 文件检查列表
    pub file: Option<Vec<FileCheck>>,
    /// 工作流定义
    pub workflows: Option<Vec<WorkflowStep>>,
    /// 变量定义
    pub variables: Option<HashMap<String, String>>,
    /// 参考链接
    pub reference: Option<String>,
}

/// DNS请求定义
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsRequest {
    /// DNS查询名称
    pub name: String,
    /// 查询类型 (A, AAAA, CNAME, MX, TXT, NS, PTR, SOA, SRV等)
    #[serde(rename = "type")]
    pub query_type: Option<String>,
    /// 查询类别 (通常为IN)
    pub class: Option<String>,
    /// 递归查询标志
    pub recursion: Option<bool>,
    /// DNS服务器地址
    pub resolvers: Option<Vec<String>>,
    /// 查询超时时间（秒）
    pub timeout: Option<u64>,
    /// 重试次数
    pub retries: Option<u32>,
    /// 匹配器
    pub matchers: Option<Vec<Matcher>>,
    /// 提取器
    pub extractors: Option<Vec<Extractor>>,
}

/// 网络请求定义
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkRequest {
    /// 目标主机
    pub host: Option<Vec<String>>,
    /// 目标端口
    pub port: Option<Vec<String>>,
    /// 输入数据（要发送的数据）
    pub inputs: Option<Vec<String>>,
    /// 读取大小
    #[serde(rename = "read-size")]
    pub read_size: Option<u32>,
    /// 连接超时时间（毫秒）
    pub timeout: Option<u64>,
    /// 协议类型 (tcp, udp)
    pub protocol: Option<String>,
    /// 是否使用TLS
    pub tls: Option<bool>,
    /// 匹配器
    pub matchers: Option<Vec<Matcher>>,
    /// 提取器
    pub extractors: Option<Vec<Extractor>>,
}

/// 文件检查定义
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileCheck {
    /// 文件扩展名过滤
    pub extensions: Option<Vec<String>>,
    /// 文件路径模式
    pub paths: Option<Vec<String>>,
    /// 文件大小限制（字节）
    pub max_size: Option<u64>,
    /// 是否递归检查子目录
    pub recursive: Option<bool>,
    /// 排除的文件模式
    pub exclude: Option<Vec<String>>,
    /// 文件内容编码
    pub encoding: Option<String>,
    /// 匹配器
    pub matchers: Option<Vec<Matcher>>,
    /// 提取器
    pub extractors: Option<Vec<Extractor>>,
}

/// 模板执行结果
#[derive(Debug, Clone)]
pub struct TemplateResult {
    /// 模板ID
    pub template_id: String,
    /// 目标URL
    pub target_url: String,
    /// 是否匹配成功
    pub matched: bool,
    /// 匹配的匹配器名称
    pub matched_matchers: Vec<String>,
    /// 提取的变量
    pub extracted_vars: HashMap<String, DslValue>,
    /// 响应信息
    pub response_info: Option<ResponseInfo>,
    /// 错误信息
    pub error: Option<String>,
}

/// 响应信息
#[derive(Debug, Clone)]
pub struct ResponseInfo {
    /// 状态码
    pub status_code: u16,
    /// 响应头
    pub headers: HashMap<String, String>,
    /// 响应体
    pub body: String,
    /// 响应时间（毫秒）
    pub response_time: u64,
    /// 内容长度
    pub content_length: u64,
    /// 目标URL
    pub target_url: String,
}

impl Template {
    /// 从YAML字符串解析模板
    pub fn from_yaml(yaml_content: &str) -> Result<Self> {
        serde_yaml::from_str(yaml_content)
            .map_err(|e| crate::ScanError::InvalidInput(format!("模板解析失败: {}", e)))
    }

    /// 从文件加载模板
    pub fn from_file(file_path: &str) -> Result<Self> {
        let content = std::fs::read_to_string(file_path)
            .map_err(|e| crate::ScanError::InvalidInput(format!("无法读取模板文件 {}: {}", file_path, e)))?;
        Self::from_yaml(&content)
    }

    /// 验证模板的有效性
    pub fn validate(&self) -> Result<()> {
        // 模板ID可以为空，空的话会在加载时使用文件名代替

        // 检查是否至少有一种请求类型
        if self.http.is_none() && self.requests.is_none() && self.rules.is_none() && self.dns.is_none() && self.network.is_none() && self.file.is_none() {
            return Err(crate::ScanError::InvalidInput("模板必须包含至少一种请求类型".to_string()));
        }

        // 验证HTTP请求
        if let Some(ref http_requests) = self.http {
            for (i, request) in http_requests.iter().enumerate() {
                self.validate_http_request(request, i)?;
            }
        }

        // 验证requests字段中的HTTP请求
        if let Some(ref requests) = self.requests {
            for (i, request) in requests.iter().enumerate() {
                self.validate_http_request(request, i)?;
            }
        }

        Ok(())
    }

    /// 获取所有HTTP请求（合并http、requests和rules字段）
    pub fn get_http_requests(&self) -> Vec<&HttpRequest> {
        let mut requests = Vec::new();

        if let Some(ref http_requests) = self.http {
            requests.extend(http_requests.iter());
        }

        if let Some(ref request_list) = self.requests {
            requests.extend(request_list.iter());
        }

        // 从rules字段中提取HTTP请求
        if let Some(ref rules) = self.rules {
            for rule in rules.values() {
                if let Some(ref request) = rule.request {
                    requests.push(request);
                }
            }
        }

        requests
    }

    /// 验证HTTP请求的有效性
    fn validate_http_request(&self, request: &HttpRequest, index: usize) -> Result<()> {
        // 检查是否有路径或原始请求
        if request.path.is_none() && request.raw.is_none() {
            return Err(crate::ScanError::InvalidInput(
                format!("HTTP请求 {} 必须包含path或raw字段", index)
            ));
        }

        // 验证匹配器
        if let Some(ref matchers) = request.matchers {
            for (j, matcher) in matchers.iter().enumerate() {
                self.validate_matcher(matcher, index, j)?;
            }
        }

        Ok(())
    }

    /// 验证匹配器的有效性
    fn validate_matcher(&self, matcher: &Matcher, request_index: usize, matcher_index: usize) -> Result<()> {
        match matcher.matcher_type.as_str() {
            "status" => {
                if let Some(ref status_codes) = matcher.status {
                    if status_codes.is_empty() {
                        return Err(crate::ScanError::InvalidInput(
                            format!("HTTP请求 {} 的匹配器 {} 的状态码列表不能为空", request_index, matcher_index)
                        ));
                    }
                } else {
                    return Err(crate::ScanError::InvalidInput(
                        format!("HTTP请求 {} 的匹配器 {} 缺少状态码列表", request_index, matcher_index)
                    ));
                }
            }
            "word" => {
                if let Some(ref words) = matcher.words {
                    if words.is_empty() {
                        return Err(crate::ScanError::InvalidInput(
                            format!("HTTP请求 {} 的匹配器 {} 的单词列表不能为空", request_index, matcher_index)
                        ));
                    }
                } else {
                    return Err(crate::ScanError::InvalidInput(
                        format!("HTTP请求 {} 的匹配器 {} 缺少单词列表", request_index, matcher_index)
                    ));
                }
            }
            "regex" => {
                if let Some(ref regex_patterns) = matcher.regex {
                    if regex_patterns.is_empty() {
                        return Err(crate::ScanError::InvalidInput(
                            format!("HTTP请求 {} 的匹配器 {} 的正则表达式列表不能为空", request_index, matcher_index)
                        ));
                    }
                    // 验证正则表达式的有效性
                    for pattern in regex_patterns {
                        if let Err(e) = regex::Regex::new(pattern) {
                            return Err(crate::ScanError::InvalidInput(
                                format!("HTTP请求 {} 的匹配器 {} 包含无效的正则表达式 '{}': {}",
                                    request_index, matcher_index, pattern, e)
                            ));
                        }
                    }
                } else {
                    return Err(crate::ScanError::InvalidInput(
                        format!("HTTP请求 {} 的匹配器 {} 缺少正则表达式列表", request_index, matcher_index)
                    ));
                }
            }
            "dsl" => {
                if let Some(ref dsl_expressions) = matcher.dsl {
                    if dsl_expressions.is_empty() {
                        return Err(crate::ScanError::InvalidInput(
                            format!("HTTP请求 {} 的匹配器 {} 的DSL表达式列表不能为空", request_index, matcher_index)
                        ));
                    }
                } else {
                    return Err(crate::ScanError::InvalidInput(
                        format!("HTTP请求 {} 的匹配器 {} 缺少DSL表达式列表", request_index, matcher_index)
                    ));
                }
            }
            "size" => {
                if let Some(ref sizes) = matcher.size {
                    if sizes.is_empty() {
                        return Err(crate::ScanError::InvalidInput(
                            format!("HTTP请求 {} 的匹配器 {} 的大小列表不能为空", request_index, matcher_index)
                        ));
                    }
                }
            }
            "binary" => {
                if let Some(ref binary_patterns) = matcher.binary {
                    if binary_patterns.is_empty() {
                        return Err(crate::ScanError::InvalidInput(
                            format!("HTTP请求 {} 的匹配器 {} 的二进制模式列表不能为空", request_index, matcher_index)
                        ));
                    }
                }
            }
            _ => {
                return Err(crate::ScanError::InvalidInput(
                    format!("HTTP请求 {} 的匹配器 {} 包含未知的匹配器类型: {}",
                        request_index, matcher_index, matcher.matcher_type)
                ));
            }
        }

        Ok(())
    }

    /// 获取模板的所有标签
    pub fn get_tags(&self) -> Vec<String> {
        self.info
            .as_ref()
            .and_then(|info| info.tags.as_ref())
            .map(|tags| {
                match tags {
                    TagsInfo::Single(tag) => tag.split(',').map(|t| t.trim().to_string()).collect(),
                    TagsInfo::Multiple(tag_list) => tag_list.clone(),
                }
            })
            .unwrap_or_default()
    }

    /// 检查模板是否包含指定标签
    pub fn has_tag(&self, tag: &str) -> bool {
        self.get_tags().iter().any(|t| t.eq_ignore_ascii_case(tag))
    }
}
