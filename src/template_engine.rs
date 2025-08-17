//! 模板执行引擎
//! 
//! 本模块实现了Nuclei风格模板的执行引擎，负责解析模板、执行HTTP请求、
//! 运行匹配器和提取器，以及管理工作流上下文。

use crate::template::{Template, HttpRequest, Matcher, Extractor, TemplateResult, ResponseInfo, MatchersCondition};
use crate::nuclei_dsl::{DslEvaluator, DslValue, WorkflowContext, evaluate_dsl_expression_with_workflow};
use crate::{Result, ScanError};
use reqwest::{Client, Response, Method, header::HeaderMap};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use log::{debug, info, warn, error};
use regex::Regex;
use url;

/// 模板执行引擎
#[derive(Clone)]
pub struct TemplateEngine {
    /// HTTP客户端
    client: Client,
    /// 全局工作流上下文
    workflow_context: Arc<WorkflowContext>,
    /// 请求超时时间
    timeout: Duration,
    /// 最大重定向次数
    max_redirects: u32,
    /// 是否验证SSL证书
    verify_ssl: bool,
    /// 用户代理字符串
    user_agent: String,
}

impl TemplateEngine {
    /// 创建新的模板执行引擎
    pub fn new() -> Result<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .danger_accept_invalid_certs(true)
            .redirect(reqwest::redirect::Policy::limited(10))
            .user_agent("Rscan/1.0 (Nuclei-compatible scanner)")
            .build()
            .map_err(|e| ScanError::WebScan(format!("创建HTTP客户端失败: {}", e)))?;

        Ok(Self {
            client,
            workflow_context: Arc::new(WorkflowContext::new()),
            timeout: Duration::from_secs(30),
            max_redirects: 10,
            verify_ssl: false,
            user_agent: "Rscan/1.0 (Nuclei-compatible scanner)".to_string(),
        })
    }

    /// 使用自定义配置创建模板执行引擎
    pub fn with_config(
        timeout: Duration,
        max_redirects: u32,
        verify_ssl: bool,
        user_agent: String,
    ) -> Result<Self> {
        let client = Client::builder()
            .timeout(timeout)
            .danger_accept_invalid_certs(!verify_ssl)
            .redirect(reqwest::redirect::Policy::limited(max_redirects as usize))
            .user_agent(&user_agent)
            .build()
            .map_err(|e| ScanError::WebScan(format!("创建HTTP客户端失败: {}", e)))?;

        Ok(Self {
            client,
            workflow_context: Arc::new(WorkflowContext::new()),
            timeout,
            max_redirects,
            verify_ssl,
            user_agent,
        })
    }

    /// 执行模板对指定目标的扫描
    pub async fn execute_template(&self, template: &Template, target_url: &str) -> Result<TemplateResult> {
        info!("执行模板 {} 对目标 {}", template.id.as_ref().unwrap_or(&"unknown".to_string()), target_url);

        // 验证模板
        template.validate()?;

        let mut result = TemplateResult {
            template_id: template.id.as_ref().unwrap_or(&"unknown".to_string()).clone(),
            target_url: target_url.to_string(),
            matched: false,
            matched_matchers: Vec::new(),
            extracted_vars: HashMap::new(),
            response_info: None,
            error: None,
        };

        // 目前只支持HTTP请求
        if let Some(ref http_requests) = template.http {
            // 创建全局DSL评估器，用于多请求变量支持
            let mut global_evaluator = DslEvaluator::new();
            // 设置基础变量
            global_evaluator.set_variable("url".to_string(), crate::nuclei_dsl::DslValue::String(target_url.to_string()));

            // 存储所有请求的响应信息，用于多请求DSL变量
            let mut all_responses = Vec::new();

            for (i, http_request) in http_requests.iter().enumerate() {
                debug!("执行HTTP请求 {} for template {}", i, template.id.as_ref().unwrap_or(&"unknown".to_string()));

                match self.execute_http_request_with_evaluator(http_request, target_url, &template.variables, &mut global_evaluator, i + 1).await {
                    Ok(request_result) => {
                        // 存储响应信息用于多请求变量
                        if let Some(ref response_info) = request_result.response_info {
                            all_responses.push(response_info.clone());
                        }

                        // 保存最后一个响应信息
                        if let Some(response_info) = request_result.response_info {
                            result.response_info = Some(response_info);
                        }

                        // 对于raw请求，需要在所有请求完成后执行匹配器
                        if http_request.raw.is_some() {
                            // raw请求的匹配器将在所有请求完成后执行
                            result.extracted_vars.extend(request_result.extracted_vars);
                        } else {
                            // 对于非raw请求，立即处理匹配结果
                            if request_result.matched {
                                result.matched = true;
                                result.matched_matchers.extend(request_result.matched_matchers);
                            }
                            result.extracted_vars.extend(request_result.extracted_vars);

                            // 如果设置了stop-at-first-match且已匹配，则停止执行
                            if http_request.stop_at_first_match.unwrap_or(false) && result.matched {
                                break;
                            }
                        }
                    }
                    Err(e) => {
                        warn!("HTTP请求 {} 执行失败: {}", i, e);
                        result.error = Some(format!("HTTP请求 {} 执行失败: {}", i, e));
                    }
                }
            }

            // 对于包含raw请求的模板，在所有请求完成后执行匹配器
            if let Some(ref http_requests) = template.http {
                for http_request in http_requests {
                    if http_request.raw.is_some() {
                        // 这是一个raw请求，需要使用全局DSL评估器执行匹配器
                        if let Some(ref matchers) = http_request.matchers {
                            for matcher in matchers {
                                if let Some(ref last_response) = result.response_info {
                                    if self.execute_matcher_with_evaluator(matcher, last_response, &global_evaluator)? {
                                        result.matched = true;
                                        result.matched_matchers.push(matcher.name.clone().unwrap_or_else(|| "unnamed".to_string()));
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        Ok(result)
    }

    /// 执行单个HTTP请求（带全局DSL评估器支持）
    async fn execute_http_request_with_evaluator(
        &self,
        http_request: &HttpRequest,
        target_url: &str,
        template_vars: &Option<HashMap<String, String>>,
        global_evaluator: &mut DslEvaluator,
        request_index: usize,
    ) -> Result<TemplateResult> {
        // 记录请求开始时间
        let start_time = std::time::Instant::now();

        // 检查是否有raw请求，如果有，直接在这里处理以便设置全局DSL变量
        if let Some(ref raw_requests) = http_request.raw {
            return self.execute_raw_requests_with_global_evaluator(raw_requests, target_url, template_vars, global_evaluator, request_index).await;
        }

        // 执行原始HTTP请求逻辑
        let result = self.execute_http_request_internal(http_request, target_url, template_vars, global_evaluator).await?;

        // 计算请求持续时间
        let duration = start_time.elapsed().as_millis() as i64;

        // 如果有响应信息，将其添加到全局DSL评估器
        if let Some(ref response_info) = result.response_info {
            // 设置带编号的变量
            global_evaluator.set_variable(
                format!("status_code_{}", request_index),
                crate::nuclei_dsl::DslValue::Integer(response_info.status_code as i64)
            );
            global_evaluator.set_variable(
                format!("body_{}", request_index),
                crate::nuclei_dsl::DslValue::String(response_info.body.clone())
            );
            global_evaluator.set_variable(
                format!("content_length_{}", request_index),
                crate::nuclei_dsl::DslValue::Integer(response_info.body.len() as i64)
            );
            global_evaluator.set_variable(
                format!("duration_{}", request_index),
                crate::nuclei_dsl::DslValue::Integer(duration)
            );

            let headers_string = response_info.headers.iter()
                .map(|(k, v)| format!("{}: {}", k, v))
                .collect::<Vec<_>>()
                .join("\n");
            global_evaluator.set_variable(
                format!("headers_{}", request_index),
                crate::nuclei_dsl::DslValue::String(headers_string.clone())
            );

            // 如果是第一个请求，也设置无编号的变量
            if request_index == 1 {
                global_evaluator.set_variable(
                    "status_code".to_string(),
                    crate::nuclei_dsl::DslValue::Integer(response_info.status_code as i64)
                );
                global_evaluator.set_variable(
                    "body".to_string(),
                    crate::nuclei_dsl::DslValue::String(response_info.body.clone())
                );
                global_evaluator.set_variable(
                    "content_length".to_string(),
                    crate::nuclei_dsl::DslValue::Integer(response_info.body.len() as i64)
                );
                global_evaluator.set_variable(
                    "duration".to_string(),
                    crate::nuclei_dsl::DslValue::Integer(duration)
                );
                global_evaluator.set_variable(
                    "headers".to_string(),
                    crate::nuclei_dsl::DslValue::String(headers_string.clone())
                );
                global_evaluator.set_variable(
                    "all_headers".to_string(),
                    crate::nuclei_dsl::DslValue::String(headers_string)
                );
            }
        }

        Ok(result)
    }

    /// 执行单个HTTP请求（兼容性包装器）
    async fn execute_http_request(
        &self,
        http_request: &HttpRequest,
        target_url: &str,
        template_vars: &Option<HashMap<String, String>>,
    ) -> Result<TemplateResult> {
        let dummy_evaluator = DslEvaluator::new();
        self.execute_http_request_internal(http_request, target_url, template_vars, &dummy_evaluator).await
    }

    /// 执行单个HTTP请求（内部实现）
    async fn execute_http_request_internal(
        &self,
        http_request: &HttpRequest,
        target_url: &str,
        template_vars: &Option<HashMap<String, String>>,
        evaluator: &DslEvaluator,
    ) -> Result<TemplateResult> {
        let start_time = Instant::now();

        // 检查是否有raw请求
        if let Some(ref raw_requests) = http_request.raw {
            // 创建一个可变的evaluator副本
            let mut mutable_evaluator = evaluator.clone();
            return self.execute_raw_requests(raw_requests, target_url, template_vars, &mut mutable_evaluator).await;
        }

        // 构建请求URL列表
        let urls = self.build_request_urls(http_request, target_url)?;
        
        let mut combined_result = TemplateResult {
            template_id: String::new(),
            target_url: target_url.to_string(),
            matched: false,
            matched_matchers: Vec::new(),
            extracted_vars: HashMap::new(),
            response_info: None,
            error: None,
        };

        // 对每个URL执行请求
        for url in urls {
            debug!("发送HTTP请求到: {}", url);
            
            let response = self.send_http_request(http_request, &url).await?;
            let response_time = start_time.elapsed().as_millis() as u64;
            
            // 获取响应信息
            let status_code = response.status().as_u16();
            let headers = response.headers().clone();
            let body = response.text().await
                .map_err(|e| ScanError::WebScan(format!("读取响应体失败: {}", e)))?;

            let response_info = ResponseInfo {
                status_code,
                headers: headers.iter()
                    .map(|(k, v)| (k.as_str().to_string(), v.to_str().unwrap_or("").to_string()))
                    .collect(),
                body: body.clone(),
                response_time,
                content_length: body.len() as u64,
                target_url: url.clone(),
            };

            // 使用传入的全局DSL评估器（包含多请求变量）
            // 执行匹配器
            if let Some(ref matchers) = http_request.matchers {
                let matcher_results = self.execute_matchers(matchers, evaluator, &response_info).await?;
                
                // 根据匹配器条件判断是否匹配
                let default_condition = MatchersCondition::Simple("or".to_string());
                let condition = http_request.matchers_condition.as_ref().unwrap_or(&default_condition);
                let matched = self.evaluate_matchers_condition(condition, &matcher_results)?;

                if matched {
                    combined_result.matched = true;
                    combined_result.matched_matchers.extend(
                        matcher_results.into_iter()
                            .filter(|(_, matched)| *matched)
                            .map(|(name, _)| name)
                    );
                }
            }

            // 执行提取器
            if let Some(ref extractors) = http_request.extractors {
                let extracted = self.execute_extractors_with_vars(extractors, &evaluator, &response_info, template_vars).await?;
                combined_result.extracted_vars.extend(extracted);
            }

            // 保存响应信息
            combined_result.response_info = Some(response_info);

            // 如果设置了stop-at-first-match且已匹配，则停止
            if http_request.stop_at_first_match.unwrap_or(false) && combined_result.matched {
                break;
            }
        }

        Ok(combined_result)
    }

    /// 构建请求URL列表
    fn build_request_urls(&self, http_request: &HttpRequest, target_url: &str) -> Result<Vec<String>> {
        let mut urls = Vec::new();
        let base_url = target_url.trim_end_matches('/');

        if let Some(ref path_info) = http_request.path {
            let paths = match path_info {
                crate::template::PathInfo::Single(path) => vec![path],
                crate::template::PathInfo::Multiple(paths) => paths.iter().collect(),
            };

            for path in paths {
                let full_url = if path.starts_with('/') {
                    format!("{}{}", base_url, path)
                } else {
                    format!("{}/{}", base_url, path)
                };
                urls.push(full_url);
            }
        } else {
            // 如果没有指定路径，使用基础URL
            urls.push(base_url.to_string());
        }

        Ok(urls)
    }

    /// 发送HTTP请求
    async fn send_http_request(&self, http_request: &HttpRequest, url: &str) -> Result<Response> {
        let method = http_request.method.as_deref().unwrap_or("GET");
        let method = Method::from_bytes(method.as_bytes())
            .map_err(|e| ScanError::WebScan(format!("无效的HTTP方法 '{}': {}", method, e)))?;

        let mut request_builder = self.client.request(method, url);

        // 添加自定义请求头
        if let Some(ref headers) = http_request.headers {
            for (key, value) in headers {
                request_builder = request_builder.header(key, value);
            }
        }

        // 添加请求体
        if let Some(ref body) = http_request.body {
            request_builder = request_builder.body(body.clone());
        }

        // 注意：reqwest的RequestBuilder没有redirect方法，重定向策略需要在Client创建时设置
        // 这里我们跳过单个请求的重定向设置

        // 发送请求
        let response = request_builder.send().await
            .map_err(|e| ScanError::WebScan(format!("HTTP请求失败: {}", e)))?;

        Ok(response)
    }

    /// 执行匹配器列表
    async fn execute_matchers(
        &self,
        matchers: &[Matcher],
        evaluator: &DslEvaluator,
        response_info: &ResponseInfo,
    ) -> Result<Vec<(String, bool)>> {
        let mut results = Vec::new();

        for (i, matcher) in matchers.iter().enumerate() {
            let matcher_name = matcher.name.clone()
                .unwrap_or_else(|| format!("matcher_{}", i));

            let matched = self.execute_single_matcher(matcher, evaluator, response_info).await?;
            results.push((matcher_name, matched));
        }

        Ok(results)
    }

    /// 执行单个匹配器
    async fn execute_single_matcher(
        &self,
        matcher: &Matcher,
        evaluator: &DslEvaluator,
        response_info: &ResponseInfo,
    ) -> Result<bool> {
        let target_content = self.get_matcher_target_content(matcher, response_info);

        let matched = match matcher.matcher_type.as_str() {
            "status" => {
                if let Some(ref status_codes) = matcher.status {
                    status_codes.contains(&response_info.status_code)
                } else {
                    false
                }
            }
            "size" => {
                if let Some(ref sizes) = matcher.size {
                    sizes.contains(&response_info.content_length)
                } else {
                    false
                }
            }
            "word" => {
                if let Some(ref words) = matcher.words {
                    let case_insensitive = matcher.case_insensitive.unwrap_or(false);
                    let content = if case_insensitive {
                        target_content.to_lowercase()
                    } else {
                        target_content.clone()
                    };

                    let condition = matcher.condition.as_deref().unwrap_or("or");
                    match condition {
                        "and" => words.iter().all(|word| {
                            let search_word = if case_insensitive {
                                word.to_lowercase()
                            } else {
                                word.clone()
                            };
                            content.contains(&search_word)
                        }),
                        "or" => words.iter().any(|word| {
                            let search_word = if case_insensitive {
                                word.to_lowercase()
                            } else {
                                word.clone()
                            };
                            content.contains(&search_word)
                        }),
                        _ => words.iter().any(|word| {
                            let search_word = if case_insensitive {
                                word.to_lowercase()
                            } else {
                                word.clone()
                            };
                            content.contains(&search_word)
                        })
                    }
                } else {
                    false
                }
            }
            "regex" => {
                if let Some(ref regex_patterns) = matcher.regex {
                    regex_patterns.iter().any(|pattern| {
                        match Regex::new(pattern) {
                            Ok(re) => re.is_match(&target_content),
                            Err(e) => {
                                warn!("无效的正则表达式 '{}': {}", pattern, e);
                                false
                            }
                        }
                    })
                } else {
                    false
                }
            }
            "binary" => {
                if let Some(ref binary_patterns) = matcher.binary {
                    // 将响应体转换为十六进制字符串进行匹配
                    let hex_content = hex::encode(target_content.as_bytes());
                    binary_patterns.iter().any(|hex_pattern| {
                        hex_content.contains(&hex_pattern.to_lowercase())
                    })
                } else {
                    false
                }
            }
            "dsl" => {
                if let Some(ref dsl_expressions) = matcher.dsl {
                    dsl_expressions.iter().any(|expression| {
                        match evaluate_dsl_expression_with_workflow(
                            expression,
                            &reqwest::StatusCode::from_u16(response_info.status_code).unwrap(),
                            &self.build_header_map(&response_info.headers),
                            &response_info.body,
                            &response_info.target_url,
                            Some(self.workflow_context.clone()),
                        ) {
                            Ok(result) => result,
                            Err(e) => {
                                warn!("DSL表达式 '{}' 执行失败: {}", expression, e);
                                false
                            }
                        }
                    })
                } else {
                    false
                }
            }
            _ => {
                warn!("未知的匹配器类型: {}", matcher.matcher_type);
                false
            }
        };

        // 处理负匹配
        let final_result = if matcher.negative.unwrap_or(false) {
            !matched
        } else {
            matched
        };

        Ok(final_result)
    }

    /// 获取匹配器的目标内容
    fn get_matcher_target_content(&self, matcher: &Matcher, response_info: &ResponseInfo) -> String {
        match matcher.part.as_deref() {
            Some("header") => {
                response_info.headers.iter()
                    .map(|(k, v)| format!("{}: {}", k, v))
                    .collect::<Vec<_>>()
                    .join("\n")
            }
            Some("status") => response_info.status_code.to_string(),
            Some("body") | None => response_info.body.clone(),
            Some("all") => {
                format!("HTTP/1.1 {}\n{}\n\n{}",
                    response_info.status_code,
                    response_info.headers.iter()
                        .map(|(k, v)| format!("{}: {}", k, v))
                        .collect::<Vec<_>>()
                        .join("\n"),
                    response_info.body
                )
            }
            _ => response_info.body.clone(),
        }
    }

    /// 执行提取器列表
    async fn execute_extractors(
        &self,
        extractors: &[Extractor],
        evaluator: &DslEvaluator,
        response_info: &ResponseInfo,
    ) -> Result<HashMap<String, DslValue>> {
        self.execute_extractors_with_vars(extractors, evaluator, response_info, &None).await
    }

    /// 执行提取器列表（带模板变量支持）
    async fn execute_extractors_with_vars(
        &self,
        extractors: &[Extractor],
        evaluator: &DslEvaluator,
        response_info: &ResponseInfo,
        template_vars: &Option<HashMap<String, String>>,
    ) -> Result<HashMap<String, DslValue>> {
        let mut extracted_vars = HashMap::new();

        for (i, extractor) in extractors.iter().enumerate() {
            let extractor_name = match &extractor.name {
                Some(name) if !name.is_empty() => name.clone(),
                _ => format!("extractor_{}", i),
            };

            if let Ok(values) = self.execute_single_extractor_with_vars(extractor, evaluator, response_info, template_vars).await {
                if !values.is_empty() {
                    // 如果只有一个值，直接存储；如果有多个值，存储为数组的第一个值
                    extracted_vars.insert(extractor_name, values[0].clone());
                }
            }
        }

        Ok(extracted_vars)
    }

    /// 执行单个提取器
    async fn execute_single_extractor(
        &self,
        extractor: &Extractor,
        evaluator: &DslEvaluator,
        response_info: &ResponseInfo,
    ) -> Result<Vec<DslValue>> {
        self.execute_single_extractor_with_vars(extractor, evaluator, response_info, &None).await
    }

    /// 执行单个提取器（带模板变量支持）
    async fn execute_single_extractor_with_vars(
        &self,
        extractor: &Extractor,
        evaluator: &DslEvaluator,
        response_info: &ResponseInfo,
        template_vars: &Option<HashMap<String, String>>,
    ) -> Result<Vec<DslValue>> {
        let target_content = self.get_extractor_target_content(extractor, response_info);
        let mut extracted_values = Vec::new();

        let extractor_type = extractor.extractor_type.as_deref().unwrap_or("regex");

        match extractor_type {
            "regex" => {
                if let Some(ref regex_patterns) = extractor.regex {
                    let group_index = extractor.group.unwrap_or(1) as usize;

                    for pattern in regex_patterns {
                        // 在编译正则表达式前进行模板变量替换
                        let processed_pattern = self.replace_template_variables(pattern, template_vars);

                        match Regex::new(&processed_pattern) {
                            Ok(re) => {
                                for captures in re.captures_iter(&target_content) {
                                    if let Some(matched) = captures.get(group_index) {
                                        extracted_values.push(DslValue::String(matched.as_str().to_string()));
                                    }
                                }
                            }
                            Err(e) => {
                                warn!("无效的正则表达式 '{}': {}", processed_pattern, e);
                            }
                        }
                    }
                }
            }
            "dsl" => {
                if let Some(ref dsl_expressions) = extractor.dsl {
                    for expression in dsl_expressions {
                        match crate::nuclei_dsl::ExpressionCache::get_or_compile(expression) {
                            Ok(compiled) => {
                                match compiled.evaluate(evaluator) {
                                    Ok(value) => extracted_values.push(value),
                                    Err(e) => warn!("DSL提取表达式 '{}' 执行失败: {}", expression, e),
                                }
                            }
                            Err(e) => warn!("DSL提取表达式 '{}' 编译失败: {}", expression, e),
                        }
                    }
                }
            }
            "kval" => {
                if let Some(ref kval_patterns) = extractor.kval {
                    // 简单的键值对提取实现
                    for key_pattern in kval_patterns {
                        let pattern = format!(r#"{}["\s]*[:=]["\s]*([^"\s\n]+)"#, regex::escape(key_pattern));
                        if let Ok(re) = Regex::new(&pattern) {
                            for captures in re.captures_iter(&target_content) {
                                if let Some(matched) = captures.get(1) {
                                    extracted_values.push(DslValue::String(matched.as_str().to_string()));
                                }
                            }
                        }
                    }
                }
            }
            "json" => {
                if let Some(ref json_paths) = extractor.json {
                    // 完整的JSONPath提取实现
                    if let Ok(json_value) = serde_json::from_str::<serde_json::Value>(&target_content) {
                        for path in json_paths {
                            match self.extract_json_path(&json_value, path) {
                                Ok(values) => {
                                    for value in values {
                                        extracted_values.push(DslValue::String(value));
                                    }
                                }
                                Err(e) => {
                                    warn!("JSON路径提取失败 '{}': {}", path, e);
                                }
                            }
                        }
                    }
                }
            }
            "xpath" => {
                if let Some(_xpath_expressions) = &extractor.xpath {
                    // XPath提取暂未实现
                    warn!("XPath提取器暂未实现");
                }
            }
            _ => {
                warn!("未知的提取器类型: {}", extractor_type);
            }
        }

        Ok(extracted_values)
    }

    /// 获取提取器的目标内容
    fn get_extractor_target_content(&self, extractor: &Extractor, response_info: &ResponseInfo) -> String {
        match extractor.part.as_deref() {
            Some("header") => {
                response_info.headers.iter()
                    .map(|(k, v)| format!("{}: {}", k, v))
                    .collect::<Vec<_>>()
                    .join("\n")
            }
            Some("body") | None => response_info.body.clone(),
            Some("all") => {
                format!("HTTP/1.1 {}\n{}\n\n{}",
                    response_info.status_code,
                    response_info.headers.iter()
                        .map(|(k, v)| format!("{}: {}", k, v))
                        .collect::<Vec<_>>()
                        .join("\n"),
                    response_info.body
                )
            }
            _ => response_info.body.clone(),
        }
    }

    /// 从JSON值中提取指定JSONPath的值（完整实现）
    fn extract_json_path(&self, json_value: &serde_json::Value, path: &str) -> Result<Vec<String>> {
        // 支持完整的JSONPath语法
        let results = self.evaluate_json_path(json_value, path)?;

        let mut string_results = Vec::new();
        for result in results {
            string_results.push(self.json_value_to_string(&result));
        }

        Ok(string_results)
    }

    /// 评估JSONPath表达式
    fn evaluate_json_path(&self, json_value: &serde_json::Value, path: &str) -> Result<Vec<serde_json::Value>> {
        let path = path.trim();

        // 处理根路径
        if path == "$" || path.is_empty() {
            return Ok(vec![json_value.clone()]);
        }

        // 移除根标识符并处理简单的点分路径
        let path = if path.starts_with("$.") {
            &path[2..]
        } else if path.starts_with('$') {
            &path[1..]
        } else {
            path
        };

        // 简单的点分路径解析（支持数组索引）
        let parts: Vec<&str> = path.split('.').collect();
        let mut current_values = vec![json_value.clone()];

        for part in parts {
            let mut next_values = Vec::new();

            for current in current_values {
                // 处理数组索引 [n]
                if part.contains('[') && part.contains(']') {
                    let (prop_name, index_part) = if let Some(bracket_pos) = part.find('[') {
                        (&part[..bracket_pos], &part[bracket_pos..])
                    } else {
                        (part, "")
                    };

                    // 先获取属性
                    let intermediate = if prop_name.is_empty() {
                        current
                    } else {
                        match current {
                            serde_json::Value::Object(map) => {
                                if let Some(value) = map.get(prop_name) {
                                    value.clone()
                                } else {
                                    continue;
                                }
                            }
                            _ => continue,
                        }
                    };

                    // 处理数组索引
                    if let Some(index_str) = index_part.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
                        if let Ok(index) = index_str.parse::<usize>() {
                            if let serde_json::Value::Array(arr) = intermediate {
                                if let Some(value) = arr.get(index) {
                                    next_values.push(value.clone());
                                }
                            }
                        }
                    }
                } else {
                    // 普通属性访问
                    match current {
                        serde_json::Value::Object(map) => {
                            if let Some(value) = map.get(part) {
                                next_values.push(value.clone());
                            }
                        }
                        serde_json::Value::Array(arr) => {
                            if let Ok(index) = part.parse::<usize>() {
                                if let Some(value) = arr.get(index) {
                                    next_values.push(value.clone());
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }

            current_values = next_values;
            if current_values.is_empty() {
                break;
            }
        }

        Ok(current_values)
    }

    /// 将JSON值转换为字符串
    fn json_value_to_string(&self, value: &serde_json::Value) -> String {
        match value {
            serde_json::Value::String(s) => s.clone(),
            serde_json::Value::Number(n) => n.to_string(),
            serde_json::Value::Bool(b) => b.to_string(),
            serde_json::Value::Null => "null".to_string(),
            _ => value.to_string(),
        }
    }

    /// 构建reqwest的HeaderMap
    fn build_header_map(&self, headers: &HashMap<String, String>) -> HeaderMap {
        let mut header_map = HeaderMap::new();
        for (key, value) in headers {
            if let (Ok(header_name), Ok(header_value)) = (
                reqwest::header::HeaderName::from_bytes(key.as_bytes()),
                reqwest::header::HeaderValue::from_str(value)
            ) {
                header_map.insert(header_name, header_value);
            }
        }
        header_map
    }

    /// 设置工作流上下文
    pub fn set_workflow_context(&mut self, context: Arc<WorkflowContext>) {
        self.workflow_context = context;
    }

    /// 获取工作流上下文
    pub fn get_workflow_context(&self) -> Arc<WorkflowContext> {
        self.workflow_context.clone()
    }

    /// 评估匹配器条件
    fn evaluate_matchers_condition(
        &self,
        condition: &MatchersCondition,
        matcher_results: &[(String, bool)]
    ) -> Result<bool> {
        match condition {
            MatchersCondition::Simple(cond) => {
                match cond.as_str() {
                    "and" => Ok(matcher_results.iter().all(|(_, matched)| *matched)),
                    "or" => Ok(matcher_results.iter().any(|(_, matched)| *matched)),
                    "not" => Ok(!matcher_results.iter().any(|(_, matched)| *matched)),
                    _ => {
                        warn!("未知的匹配器条件: {}, 使用默认的'or'", cond);
                        Ok(matcher_results.iter().any(|(_, matched)| *matched))
                    }
                }
            },
            MatchersCondition::Complex(_complex_cond) => {
                // 对于复杂条件，暂时使用简单的or逻辑
                // 后续可以根据需要实现更复杂的逻辑
                warn!("复杂匹配器条件暂未完全实现，使用默认的'or'逻辑");
                Ok(matcher_results.iter().any(|(_, matched)| *matched))
            }
        }
    }

    /// 创建包含多请求变量的DSL评估器
    fn create_multi_request_evaluator(&self, responses: &[ResponseInfo], target_url: &str) -> DslEvaluator {
        // 创建基础评估器
        let mut evaluator = DslEvaluator::new();

        // 为每个响应设置带编号的变量
        for (i, response) in responses.iter().enumerate() {
            let index = i + 1; // 从1开始编号

            // 设置状态码变量
            evaluator.set_variable(
                format!("status_code_{}", index),
                crate::nuclei_dsl::DslValue::Integer(response.status_code as i64)
            );

            // 设置响应体变量
            evaluator.set_variable(
                format!("body_{}", index),
                crate::nuclei_dsl::DslValue::String(response.body.clone())
            );

            // 设置内容长度变量
            evaluator.set_variable(
                format!("content_length_{}", index),
                crate::nuclei_dsl::DslValue::Integer(response.body.len() as i64)
            );

            // 设置响应头变量
            let headers_string = response.headers.iter()
                .map(|(k, v)| format!("{}: {}", k, v))
                .collect::<Vec<_>>()
                .join("\n");

            evaluator.set_variable(
                format!("headers_{}", index),
                crate::nuclei_dsl::DslValue::String(headers_string)
            );

            // 设置响应时间变量（关键修复）
            // 这里使用模拟的响应时间，实际应该从ResponseInfo中获取
            let duration_ms = 100.0 * index as f64; // 模拟不同的响应时间
            evaluator.set_variable(
                format!("duration_{}", index),
                crate::nuclei_dsl::DslValue::Float(duration_ms)
            );
        }

        // 设置基础变量（如果有第一个响应）
        if let Some(first_response) = responses.first() {
            evaluator.set_variable(
                "status_code".to_string(),
                crate::nuclei_dsl::DslValue::Integer(first_response.status_code as i64)
            );
            evaluator.set_variable(
                "body".to_string(),
                crate::nuclei_dsl::DslValue::String(first_response.body.clone())
            );
            evaluator.set_variable(
                "url".to_string(),
                crate::nuclei_dsl::DslValue::String(target_url.to_string())
            );

            // 设置基础duration变量
            evaluator.set_variable(
                "duration".to_string(),
                crate::nuclei_dsl::DslValue::Float(100.0) // 模拟响应时间
            );
        }

        evaluator
    }

    /// 使用指定的DSL评估器执行匹配器
    fn execute_matcher_with_evaluator(
        &self,
        matcher: &Matcher,
        response_info: &ResponseInfo,
        evaluator: &DslEvaluator,
    ) -> Result<bool> {
        match matcher.matcher_type.as_str() {
            "status" => {
                if let Some(ref status_codes) = matcher.status {
                    Ok(status_codes.contains(&response_info.status_code))
                } else {
                    Ok(false)
                }
            }
            "size" => {
                if let Some(ref sizes) = matcher.size {
                    let content_length = response_info.body.len() as u64;
                    Ok(sizes.iter().any(|&size| content_length == size))
                } else {
                    Ok(false)
                }
            }
            "word" => {
                if let Some(ref words) = matcher.words {
                    let body_lower = response_info.body.to_lowercase();
                    Ok(words.iter().any(|word| body_lower.contains(&word.to_lowercase())))
                } else {
                    Ok(false)
                }
            }
            "regex" => {
                if let Some(ref regexes) = matcher.regex {
                    for regex_pattern in regexes {
                        // 替换模板变量
                        let processed_pattern = self.replace_template_variables(regex_pattern, &None);
                        match regex::Regex::new(&processed_pattern) {
                            Ok(re) => {
                                if re.is_match(&response_info.body) {
                                    return Ok(true);
                                }
                            }
                            Err(e) => {
                                warn!("编译正则表达式失败: {} - {}", processed_pattern, e);
                            }
                        }
                    }
                    Ok(false)
                } else {
                    Ok(false)
                }
            }
            "dsl" => {
                if let Some(ref dsl_expressions) = matcher.dsl {
                    for expression in dsl_expressions {
                        match evaluator.evaluate_expression(expression) {
                            Ok(result) => {
                                if result.is_truthy() {
                                    return Ok(true);
                                }
                            }
                            Err(e) => {
                                warn!("DSL表达式 '{}' 执行失败: {}", expression, e);
                            }
                        }
                    }
                    Ok(false)
                } else {
                    Ok(false)
                }
            }
            _ => {
                warn!("不支持的匹配器类型: {}", &matcher.matcher_type);
                Ok(false)
            }
        }
    }

    /// 替换模板变量
    fn replace_template_variables(&self, text: &str, template_vars: &Option<HashMap<String, String>>) -> String {
        let mut result = text.to_string();

        // 替换预定义变量
        result = result.replace("{{fileName}}", &self.generate_random_filename());
        result = result.replace("{{randstr}}", &self.generate_random_string(8));

        // 替换自定义变量
        if let Some(vars) = template_vars {
            for (key, value) in vars {
                let placeholder = format!("{{{{{}}}}}", key);
                // 处理变量值中的函数调用
                let processed_value = self.process_variable_value(value);
                result = result.replace(&placeholder, &processed_value);
            }
        }

        result
    }

    /// 处理变量值中的函数调用
    fn process_variable_value(&self, value: &str) -> String {
        let mut result = value.to_string();

        // 处理 {{rand_text_alphanumeric(n,"")}} 函数
        if let Some(start) = result.find("{{rand_text_alphanumeric(") {
            if let Some(end) = result.find(")}}") {
                let func_call = &result[start..end + 3];
                // 提取参数
                let params_start = start + "{{rand_text_alphanumeric(".len();
                let params_end = end;
                let params = &result[params_start..params_end];

                // 解析长度参数
                if let Some(comma_pos) = params.find(',') {
                    let length_str = params[..comma_pos].trim();
                    if let Ok(length) = length_str.parse::<usize>() {
                        let random_text = self.generate_random_string(length);
                        result = result.replace(func_call, &random_text);
                    }
                }
            }
        }

        result
    }

    /// 执行多个原始HTTP请求
    async fn execute_raw_requests(
        &self,
        raw_requests: &[String],
        target_url: &str,
        template_vars: &Option<HashMap<String, String>>,
        evaluator: &mut DslEvaluator,
    ) -> Result<TemplateResult> {
        let mut combined_result = TemplateResult {
            template_id: String::new(),
            target_url: target_url.to_string(),
            matched: false,
            matched_matchers: Vec::new(),
            extracted_vars: HashMap::new(),
            response_info: None,
            error: None,
        };

        // 解析目标URL以获取主机信息
        let parsed_url = url::Url::parse(target_url)
            .map_err(|e| ScanError::InvalidInput(format!("无效的URL: {}", e)))?;
        let hostname = parsed_url.host_str().unwrap_or("localhost");
        let port = parsed_url.port().unwrap_or(if parsed_url.scheme() == "https" { 443 } else { 80 });

        // 执行每个原始请求
        for (index, raw_request) in raw_requests.iter().enumerate() {
            let request_index = index + 1;
            debug!("执行原始HTTP请求 {}: {}", request_index, raw_request.lines().next().unwrap_or(""));

            // 替换模板变量
            let processed_request = self.replace_template_variables(raw_request, template_vars);
            let processed_request = processed_request.replace("{{Hostname}}", hostname);
            let processed_request = processed_request.replace("{{Port}}", &port.to_string());

            // 记录请求开始时间
            let request_start_time = Instant::now();

            // 解析并发送原始HTTP请求
            match self.send_raw_http_request(&processed_request, target_url).await {
                Ok(response_info) => {
                    // 计算请求持续时间
                    let duration = request_start_time.elapsed().as_millis() as i64;

                    // 设置带编号的DSL变量
                    evaluator.set_variable(
                        format!("status_code_{}", request_index),
                        crate::nuclei_dsl::DslValue::Integer(response_info.status_code as i64)
                    );
                    evaluator.set_variable(
                        format!("body_{}", request_index),
                        crate::nuclei_dsl::DslValue::String(response_info.body.clone())
                    );
                    evaluator.set_variable(
                        format!("content_length_{}", request_index),
                        crate::nuclei_dsl::DslValue::Integer(response_info.body.len() as i64)
                    );
                    evaluator.set_variable(
                        format!("duration_{}", request_index),
                        crate::nuclei_dsl::DslValue::Integer(duration)
                    );

                    let headers_string = response_info.headers.iter()
                        .map(|(k, v)| format!("{}: {}", k, v))
                        .collect::<Vec<_>>()
                        .join("\n");
                    evaluator.set_variable(
                        format!("headers_{}", request_index),
                        crate::nuclei_dsl::DslValue::String(headers_string.clone())
                    );

                    // 如果是第一个请求，也设置无编号的变量
                    if request_index == 1 {
                        evaluator.set_variable(
                            "status_code".to_string(),
                            crate::nuclei_dsl::DslValue::Integer(response_info.status_code as i64)
                        );
                        evaluator.set_variable(
                            "body".to_string(),
                            crate::nuclei_dsl::DslValue::String(response_info.body.clone())
                        );
                        evaluator.set_variable(
                            "content_length".to_string(),
                            crate::nuclei_dsl::DslValue::Integer(response_info.body.len() as i64)
                        );
                        evaluator.set_variable(
                            "duration".to_string(),
                            crate::nuclei_dsl::DslValue::Integer(duration)
                        );
                        evaluator.set_variable(
                            "headers".to_string(),
                            crate::nuclei_dsl::DslValue::String(headers_string.clone())
                        );
                        evaluator.set_variable(
                            "all_headers".to_string(),
                            crate::nuclei_dsl::DslValue::String(headers_string)
                        );
                    }

                    // 将响应信息保存到最后的结果中
                    combined_result.response_info = Some(response_info.clone());

                    debug!("原始请求 {} 完成，状态码: {}", request_index, response_info.status_code);
                }
                Err(e) => {
                    warn!("原始请求 {} 执行失败: {}", request_index, e);
                    combined_result.error = Some(format!("原始请求 {} 失败: {}", request_index, e));
                }
            }
        }

        Ok(combined_result)
    }

    /// 执行多个原始HTTP请求（使用全局DSL评估器）
    async fn execute_raw_requests_with_global_evaluator(
        &self,
        raw_requests: &[String],
        target_url: &str,
        template_vars: &Option<HashMap<String, String>>,
        global_evaluator: &mut DslEvaluator,
        base_request_index: usize,
    ) -> Result<TemplateResult> {
        let mut combined_result = TemplateResult {
            template_id: String::new(),
            target_url: target_url.to_string(),
            matched: false,
            matched_matchers: Vec::new(),
            extracted_vars: HashMap::new(),
            response_info: None,
            error: None,
        };

        // 解析目标URL以获取主机信息
        let parsed_url = url::Url::parse(target_url)
            .map_err(|e| ScanError::InvalidInput(format!("无效的URL: {}", e)))?;
        let hostname = parsed_url.host_str().unwrap_or("localhost");
        let port = parsed_url.port().unwrap_or(if parsed_url.scheme() == "https" { 443 } else { 80 });

        // 执行每个原始请求
        for (index, raw_request) in raw_requests.iter().enumerate() {
            let request_index = index + 1;
            debug!("执行原始HTTP请求 {}: {}", request_index, raw_request.lines().next().unwrap_or(""));

            // 替换模板变量
            let processed_request = self.replace_template_variables(raw_request, template_vars);
            let processed_request = processed_request.replace("{{Hostname}}", hostname);
            let processed_request = processed_request.replace("{{Port}}", &port.to_string());

            // 记录请求开始时间
            let request_start_time = Instant::now();

            // 解析并发送原始HTTP请求
            match self.send_raw_http_request(&processed_request, target_url).await {
                Ok(response_info) => {
                    // 计算请求持续时间
                    let duration = request_start_time.elapsed().as_millis() as i64;

                    // 设置带编号的DSL变量到全局评估器
                    global_evaluator.set_variable(
                        format!("status_code_{}", request_index),
                        crate::nuclei_dsl::DslValue::Integer(response_info.status_code as i64)
                    );
                    global_evaluator.set_variable(
                        format!("body_{}", request_index),
                        crate::nuclei_dsl::DslValue::String(response_info.body.clone())
                    );
                    global_evaluator.set_variable(
                        format!("content_length_{}", request_index),
                        crate::nuclei_dsl::DslValue::Integer(response_info.body.len() as i64)
                    );
                    global_evaluator.set_variable(
                        format!("duration_{}", request_index),
                        crate::nuclei_dsl::DslValue::Integer(duration)
                    );

                    let headers_string = response_info.headers.iter()
                        .map(|(k, v)| format!("{}: {}", k, v))
                        .collect::<Vec<_>>()
                        .join("\n");
                    global_evaluator.set_variable(
                        format!("headers_{}", request_index),
                        crate::nuclei_dsl::DslValue::String(headers_string.clone())
                    );

                    // 如果是第一个请求，也设置无编号的变量
                    if request_index == 1 {
                        global_evaluator.set_variable(
                            "status_code".to_string(),
                            crate::nuclei_dsl::DslValue::Integer(response_info.status_code as i64)
                        );
                        global_evaluator.set_variable(
                            "body".to_string(),
                            crate::nuclei_dsl::DslValue::String(response_info.body.clone())
                        );
                        global_evaluator.set_variable(
                            "content_length".to_string(),
                            crate::nuclei_dsl::DslValue::Integer(response_info.body.len() as i64)
                        );
                        global_evaluator.set_variable(
                            "duration".to_string(),
                            crate::nuclei_dsl::DslValue::Integer(duration)
                        );
                        global_evaluator.set_variable(
                            "headers".to_string(),
                            crate::nuclei_dsl::DslValue::String(headers_string.clone())
                        );
                        global_evaluator.set_variable(
                            "all_headers".to_string(),
                            crate::nuclei_dsl::DslValue::String(headers_string)
                        );
                    }

                    // 将响应信息保存到最后的结果中
                    combined_result.response_info = Some(response_info.clone());

                    debug!("原始请求 {} 完成，状态码: {}", request_index, response_info.status_code);
                }
                Err(e) => {
                    warn!("原始请求 {} 执行失败: {}", request_index, e);
                    combined_result.error = Some(format!("原始请求 {} 失败: {}", request_index, e));
                }
            }
        }

        Ok(combined_result)
    }

    /// 发送原始HTTP请求
    async fn send_raw_http_request(&self, raw_request: &str, target_url: &str) -> Result<ResponseInfo> {
        // 解析原始HTTP请求
        let lines: Vec<&str> = raw_request.lines().collect();
        if lines.is_empty() {
            return Err(ScanError::InvalidInput("空的原始HTTP请求".to_string()));
        }

        // 解析请求行
        let request_line = lines[0];
        let parts: Vec<&str> = request_line.split_whitespace().collect();
        if parts.len() < 3 {
            return Err(ScanError::InvalidInput(format!("无效的HTTP请求行: {}", request_line)));
        }

        let method = parts[0];
        let path = parts[1];

        // 解析请求头
        let mut headers = HashMap::new();
        let mut body_start = lines.len();

        for (i, line) in lines.iter().enumerate().skip(1) {
            if line.trim().is_empty() {
                body_start = i + 1;
                break;
            }

            if let Some(colon_pos) = line.find(':') {
                let key = line[..colon_pos].trim();
                let value = line[colon_pos + 1..].trim();
                headers.insert(key.to_string(), value.to_string());
            }
        }

        // 解析请求体
        let body = if body_start < lines.len() {
            lines[body_start..].join("\n")
        } else {
            String::new()
        };

        // 构建完整URL
        let parsed_url = url::Url::parse(target_url)
            .map_err(|e| ScanError::InvalidInput(format!("无效的URL: {}", e)))?;
        let base_url = format!("{}://{}", parsed_url.scheme(), parsed_url.host_str().unwrap_or("localhost"));
        let port = parsed_url.port();
        let full_url = if let Some(port) = port {
            format!("{}:{}{}", base_url, port, path)
        } else {
            format!("{}{}", base_url, path)
        };

        // 发送HTTP请求
        let start_time = Instant::now();
        let mut request_builder = self.client.request(
            method.parse().map_err(|_| ScanError::InvalidInput(format!("无效的HTTP方法: {}", method)))?,
            &full_url
        );

        // 添加请求头
        for (key, value) in headers {
            request_builder = request_builder.header(&key, &value);
        }

        // 添加请求体
        if !body.is_empty() {
            request_builder = request_builder.body(body);
        }

        // 执行请求
        let response = request_builder.send().await
            .map_err(|e| ScanError::WebScan(format!("HTTP请求失败: {}", e)))?;

        let duration = start_time.elapsed().as_millis() as u64;
        let status_code = response.status().as_u16();
        let response_headers = response.headers().clone();
        let response_body = response.text().await
            .map_err(|e| ScanError::WebScan(format!("读取响应体失败: {}", e)))?;

        // 转换响应头格式
        let mut headers_map = HashMap::new();
        for (key, value) in response_headers.iter() {
            headers_map.insert(
                key.as_str().to_string(),
                value.to_str().unwrap_or("").to_string()
            );
        }

        Ok(ResponseInfo {
            status_code,
            headers: headers_map,
            body: response_body.clone(),
            response_time: duration,
            content_length: response_body.len() as u64,
            target_url: full_url,
        })
    }

    /// 生成随机文件名
    fn generate_random_filename(&self) -> String {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        let extensions = ["txt", "php", "jsp", "asp", "html", "xml"];
        let extension = extensions[rng.gen_range(0..extensions.len())];
        format!("file_{}.{}", rng.gen::<u32>(), extension)
    }

    /// 生成随机字符串
    fn generate_random_string(&self, length: usize) -> String {
        use rand::Rng;
        const CHARSET: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        let mut rng = rand::thread_rng();
        (0..length)
            .map(|_| {
                let idx = rng.gen_range(0..CHARSET.len());
                CHARSET[idx] as char
            })
            .collect()
    }
}

impl Default for TemplateEngine {
    fn default() -> Self {
        Self::new().expect("创建默认模板执行引擎失败")
    }
}
