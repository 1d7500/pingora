// Copyright 2024 Cloudflare, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! HTTP header objects that preserve http header cases
//!
//! Although HTTP header names are supposed to be case-insensitive for compatibility, proxies
//! ideally shouldn't alter the HTTP traffic, especially the headers they don't need to read.
//!
//! This crate provide structs and methods to preserve the headers in order to build a transparent
//! proxy.

#![allow(clippy::new_without_default)]

use bytes::BufMut;
use http::header::{AsHeaderName, HeaderName, HeaderValue};
use http::request::Builder as ReqBuilder;
use http::request::Parts as ReqParts;
use http::response::Builder as RespBuilder;
use http::response::Parts as RespParts;
use http::uri::Uri;
use pingora_error::{ErrorType::*, OrErr, Result};
use std::ops::Deref;

pub use http::method::Method;
pub use http::status::StatusCode;
pub use http::version::Version;
pub use http::HeaderMap as HMap;

mod case_header_name;
use case_header_name::CaseHeaderName;
pub use case_header_name::IntoCaseHeaderName;

pub mod prelude {
    pub use crate::RequestHeader;
}

/* an ordered header map to store the original case of each header name
HMap({
    "foo": ["Foo", "foO", "FoO"]
})
The order how HeaderMap iter over its items is "arbitrary, but consistent".
Hopefully this property makes sure this map of header names always iterates in the
same order of the map of header values.
This idea is inspaired by hyper @nox
*/
type CaseMap = HMap<CaseHeaderName>;

/// The HTTP request header type.
///
/// This type is similar to [http::request::Parts] but preserves header name case.
/// It also preserves request path even if it is not UTF-8.
///
/// [RequestHeader] implements [Deref] for [http::request::Parts] so it can be used as it in most
/// places.
#[derive(Debug)]
pub struct RequestHeader {
    base: ReqParts,
    header_name_map: Option<CaseMap>,
    // store the raw path bytes only if it is invalid utf-8
    raw_path_fallback: Vec<u8>, // can also be Box<[u8]>
}

impl AsRef<ReqParts> for RequestHeader {
    fn as_ref(&self) -> &ReqParts {
        &self.base
    }
}

impl Deref for RequestHeader {
    type Target = ReqParts;

    fn deref(&self) -> &Self::Target {
        &self.base
    }
}

impl RequestHeader {
    fn new_no_case(size_hint: Option<usize>) -> Self {
        let mut base = ReqBuilder::new().body(()).unwrap().into_parts().0;
        base.headers.reserve(http_header_map_upper_bound(size_hint));
        RequestHeader {
            base,
            header_name_map: None,
            raw_path_fallback: vec![],
        }
    }

    /// Create a new [RequestHeader] with the given method and path.
    ///
    /// The `path` can be non UTF-8.
    pub fn build(
        method: impl TryInto<Method>,
        path: &[u8],
        size_hint: Option<usize>,
    ) -> Result<Self> {
        let mut req = Self::build_no_case(method, path, size_hint)?;
        req.header_name_map = Some(CaseMap::with_capacity(http_header_map_upper_bound(
            size_hint,
        )));
        Ok(req)
    }

    /// Create a new [RequestHeader] with the given method and path without preserving header case.
    ///
    /// A [RequestHeader] created from this type is more space efficient than those from [Self::build()].
    ///
    /// Use this method if reading from or writing to HTTP/2 sessions where header case doesn't matter anyway.
    // 定义一个公共函数 `build_no_case`，它接受三个参数并返回 `Result<Self>` 类型。
    pub fn build_no_case(
        method: impl TryInto<Method>, // 接受一个泛型参数 `method`，该参数必须实现 `TryInto<Method>` 特性。
        path: &[u8],                  // `path` 参数是一个字节切片的引用，代表请求的路径。
        size_hint: Option<usize>,     // `size_hint` 是一个可选的 `usize` 类型，提供容器的大小提示。
    ) -> Result<Self> {
        // 创建一个新的请求对象 `req`，利用 `new_no_case` 函数，该函数可能根据 `size_hint` 来优化存储。
        let mut req = Self::new_no_case(size_hint);

        // 尝试将 `method` 转换为 `Method` 类型。如果转换失败，返回一个错误。
        req.base.method = method
            .try_into()
            .explain_err(InvalidHTTPHeader, |_| "invalid method")?;

        // 尝试将 `path` 字节切片转换为 UTF-8 字符串。
        if let Ok(p) = std::str::from_utf8(path) {
            // 如果转换成功，构建一个 URI。
            let uri = Uri::builder()
                .path_and_query(p) // 使用转换后的路径和查询字符串 `p` 构建 URI。
                .build() // 构建 URI。
                .explain_err(InvalidHTTPHeader, |_| format!("invalid uri {}", p))?; // 如果构建失败，返回一个错误。
            req.base.uri = uri; // 将成功构建的 URI 设置到请求的 `base` 结构中。
                                // 保持 `raw_path` 为空，因为无需重复存储。
        } else {
            // 如果 `path` 不能被转换为有效的 UTF-8 字符串，使用 `from_utf8_lossy` 方法进行容错转换。
            let lossy_str = String::from_utf8_lossy(path);
            let uri = Uri::builder()
                .path_and_query(lossy_str.as_ref()) // 使用容错转换后的路径和查询字符串构建 URI。
                .build() // 构建 URI。
                .explain_err(InvalidHTTPHeader, |_| format!("invalid uri {}", lossy_str))?; // 如果构建失败，返回一个错误。
            req.base.uri = uri; // 将成功构建的 URI 设置到请求的 `base` 结构中。
            req.raw_path_fallback = path.to_vec(); // 将原始的 `path` 字节切片存储在 `raw_path_fallback` 中，以便只读访问。
        }

        // 成功构建请求后，返回包含请求对象的 `Ok` 结果。
        Ok(req)
    }

    /// Append the header name and value to `self`.
    ///
    /// If there are already some headers under the same name, a new value will be added without
    /// any others being removed.
    pub fn append_header(
        &mut self,
        name: impl IntoCaseHeaderName,
        value: impl TryInto<HeaderValue>,
    ) -> Result<bool> {
        let header_value = value
            .try_into()
            .explain_err(InvalidHTTPHeader, |_| "invalid value while append")?;
        append_header_value(
            self.header_name_map.as_mut(),
            &mut self.base.headers,
            name,
            header_value,
        )
    }

    /// Insert the header name and value to `self`.
    ///
    /// Different from [Self::append_header()], this method will replace all other existing headers
    /// under the same name (case-insensitive).
    pub fn insert_header(
        &mut self,
        name: impl IntoCaseHeaderName,
        value: impl TryInto<HeaderValue>,
    ) -> Result<()> {
        let header_value = value
            .try_into()
            .explain_err(InvalidHTTPHeader, |_| "invalid value while insert")?;
        insert_header_value(
            self.header_name_map.as_mut(),
            &mut self.base.headers,
            name,
            header_value,
        )
    }

    /// Remove all headers under the name
    pub fn remove_header<'a, N: ?Sized>(&mut self, name: &'a N) -> Option<HeaderValue>
    where
        &'a N: 'a + AsHeaderName,
    {
        remove_header(self.header_name_map.as_mut(), &mut self.base.headers, name)
    }

    /// Write the header to the `buf` in HTTP/1.1 wire format.
    ///
    /// The header case will be preserved.
    pub fn header_to_h1_wire(&self, buf: &mut impl BufMut) {
        header_to_h1_wire(self.header_name_map.as_ref(), &self.base.headers, buf)
    }

    /// Set the request method
    pub fn set_method(&mut self, method: Method) {
        self.base.method = method;
    }

    /// Set the request URI
    pub fn set_uri(&mut self, uri: http::Uri) {
        self.base.uri = uri;
    }

    /// Return the request path in its raw format
    ///
    /// Non-UTF8 is supported.
    pub fn raw_path(&self) -> &[u8] {
        if !self.raw_path_fallback.is_empty() {
            &self.raw_path_fallback
        } else {
            // Url should always be set
            self.base
                .uri
                .path_and_query()
                .as_ref()
                .unwrap()
                .as_str()
                .as_bytes()
        }
    }

    /// Return the file extension of the path
    pub fn uri_file_extension(&self) -> Option<&str> {
        // get everything after the last '.' in path
        let (_, ext) = self
            .uri
            .path_and_query()
            .and_then(|pq| pq.path().rsplit_once('.'))?;
        Some(ext)
    }

    /// Set http version
    pub fn set_version(&mut self, version: Version) {
        self.base.version = version;
    }

    /// Clone `self` into [http::request::Parts].
    pub fn as_owned_parts(&self) -> ReqParts {
        clone_req_parts(&self.base)
    }
}

impl Clone for RequestHeader {
    fn clone(&self) -> Self {
        Self {
            base: self.as_owned_parts(),
            header_name_map: self.header_name_map.clone(),
            raw_path_fallback: self.raw_path_fallback.clone(),
        }
    }
}

// The `RequestHeader` will be the no case variant, because `ReqParts` keeps no header case
impl From<ReqParts> for RequestHeader {
    fn from(parts: ReqParts) -> RequestHeader {
        Self {
            base: parts,
            header_name_map: None,
            // no illegal path
            raw_path_fallback: vec![],
        }
    }
}

impl From<RequestHeader> for ReqParts {
    fn from(resp: RequestHeader) -> ReqParts {
        resp.base
    }
}

/// The HTTP response header type.
///
/// This type is similar to [http::response::Parts] but preserves header name case.
/// [ResponseHeader] implements [Deref] for [http::response::Parts] so it can be used as it in most
/// places.
#[derive(Debug)]
pub struct ResponseHeader {
    base: RespParts,
    // an ordered header map to store the original case of each header name
    header_name_map: Option<CaseMap>,
}

impl AsRef<RespParts> for ResponseHeader {
    fn as_ref(&self) -> &RespParts {
        &self.base
    }
}

impl Deref for ResponseHeader {
    type Target = RespParts;

    fn deref(&self) -> &Self::Target {
        &self.base
    }
}

impl Clone for ResponseHeader {
    fn clone(&self) -> Self {
        Self {
            base: self.as_owned_parts(),
            header_name_map: self.header_name_map.clone(),
        }
    }
}

// The `ResponseHeader` will be the no case variant, because `RespParts` keeps no header case
impl From<RespParts> for ResponseHeader {
    fn from(parts: RespParts) -> ResponseHeader {
        Self {
            base: parts,
            header_name_map: None,
        }
    }
}

impl From<ResponseHeader> for RespParts {
    fn from(resp: ResponseHeader) -> RespParts {
        resp.base
    }
}

impl From<Box<ResponseHeader>> for Box<RespParts> {
    fn from(resp: Box<ResponseHeader>) -> Box<RespParts> {
        Box::new(resp.base)
    }
}

impl ResponseHeader {
    fn new(size_hint: Option<usize>) -> Self {
        let mut resp_header = Self::new_no_case(size_hint);
        resp_header.header_name_map = Some(CaseMap::with_capacity(http_header_map_upper_bound(
            size_hint,
        )));
        resp_header
    }

    fn new_no_case(size_hint: Option<usize>) -> Self {
        let mut base = RespBuilder::new().body(()).unwrap().into_parts().0;
        base.headers.reserve(http_header_map_upper_bound(size_hint));
        ResponseHeader {
            base,
            header_name_map: None,
        }
    }

    /// Create a new [ResponseHeader] with the given status code.
    pub fn build(code: impl TryInto<StatusCode>, size_hint: Option<usize>) -> Result<Self> {
        let mut resp = Self::new(size_hint);
        resp.base.status = code
            .try_into()
            .explain_err(InvalidHTTPHeader, |_| "invalid status")?;
        Ok(resp)
    }

    /// Create a new [ResponseHeader] with the given status code without preserving header case.
    ///
    /// A [ResponseHeader] created from this type is more space efficient than those from [Self::build()].
    ///
    /// Use this method if reading from or writing to HTTP/2 sessions where header case doesn't matter anyway.
    pub fn build_no_case(code: impl TryInto<StatusCode>, size_hint: Option<usize>) -> Result<Self> {
        let mut resp = Self::new_no_case(size_hint);
        resp.base.status = code
            .try_into()
            .explain_err(InvalidHTTPHeader, |_| "invalid status")?;
        Ok(resp)
    }

    /// Append the header name and value to `self`.
    ///
    /// If there are already some headers under the same name, a new value will be added without
    /// any others being removed.
    pub fn append_header(
        &mut self,
        name: impl IntoCaseHeaderName,
        value: impl TryInto<HeaderValue>,
    ) -> Result<bool> {
        let header_value = value
            .try_into()
            .explain_err(InvalidHTTPHeader, |_| "invalid value while append")?;
        append_header_value(
            self.header_name_map.as_mut(),
            &mut self.base.headers,
            name,
            header_value,
        )
    }

    /// Insert the header name and value to `self`.
    ///
    /// Different from [Self::append_header()], this method will replace all other existing headers
    /// under the same name (case insensitive).
    pub fn insert_header(
        &mut self,
        name: impl IntoCaseHeaderName,
        value: impl TryInto<HeaderValue>,
    ) -> Result<()> {
        let header_value = value
            .try_into()
            .explain_err(InvalidHTTPHeader, |_| "invalid value while insert")?;
        insert_header_value(
            self.header_name_map.as_mut(),
            &mut self.base.headers,
            name,
            header_value,
        )
    }

    /// Remove all headers under the name
    pub fn remove_header<'a, N: ?Sized>(&mut self, name: &'a N) -> Option<HeaderValue>
    where
        &'a N: 'a + AsHeaderName,
    {
        remove_header(self.header_name_map.as_mut(), &mut self.base.headers, name)
    }

    /// Write the header to the `buf` in HTTP/1.1 wire format.
    ///
    /// The header case will be preserved.
    pub fn header_to_h1_wire(&self, buf: &mut impl BufMut) {
        header_to_h1_wire(self.header_name_map.as_ref(), &self.base.headers, buf)
    }

    /// Set the status code
    pub fn set_status(&mut self, status: impl TryInto<StatusCode>) -> Result<()> {
        self.base.status = status
            .try_into()
            .explain_err(InvalidHTTPHeader, |_| "invalid status")?;
        Ok(())
    }

    /// Set the HTTP version
    pub fn set_version(&mut self, version: Version) {
        self.base.version = version
    }

    /// Clone `self` into [http::response::Parts].
    pub fn as_owned_parts(&self) -> RespParts {
        clone_resp_parts(&self.base)
    }
}

fn clone_req_parts(me: &ReqParts) -> ReqParts {
    let mut parts = ReqBuilder::new()
        .method(me.method.clone())
        .uri(me.uri.clone())
        .version(me.version)
        .body(())
        .unwrap()
        .into_parts()
        .0;
    parts.headers = me.headers.clone();
    parts
}

fn clone_resp_parts(me: &RespParts) -> RespParts {
    let mut parts = RespBuilder::new()
        .status(me.status)
        .version(me.version)
        .body(())
        .unwrap()
        .into_parts()
        .0;
    parts.headers = me.headers.clone();
    parts
}

// This function returns an upper bound on the size of the header map used inside the http crate.
// As of version 0.2, there is a limit of 1 << 15 (32,768) items inside the map. There is an
// assertion against this size inside the crate, so we want to avoid panicking by not exceeding this
// upper bound.
fn http_header_map_upper_bound(size_hint: Option<usize>) -> usize {
    // Even though the crate has 1 << 15 as the max size, calls to `with_capacity` invoke a
    // function that returns the size + size / 3.
    //
    // See https://github.com/hyperium/http/blob/34a9d6bdab027948d6dea3b36d994f9cbaf96f75/src/header/map.rs#L3220
    //
    // Therefore we set our max size to be even lower, so we guarantee ourselves we won't hit that
    // upper bound in the crate. Any way you cut it, 4,096 headers is insane.
    const PINGORA_MAX_HEADER_COUNT: usize = 4096;
    const INIT_HEADER_SIZE: usize = 8;

    // We select the size hint or the max size here, ensuring that we pick a value substantially lower
    // than 1 << 15 with room to grow the header map.
    std::cmp::min(
        size_hint.unwrap_or(INIT_HEADER_SIZE),
        PINGORA_MAX_HEADER_COUNT,
    )
}

#[inline]
fn append_header_value<T>(
    name_map: Option<&mut CaseMap>,
    value_map: &mut HMap<T>,
    name: impl IntoCaseHeaderName,
    value: T,
) -> Result<bool> {
    let case_header_name = name.into_case_header_name();
    let header_name: HeaderName = case_header_name
        .as_slice()
        .try_into()
        .or_err(InvalidHTTPHeader, "invalid header name")?;
    // store the original case in the map
    if let Some(name_map) = name_map {
        name_map.append(header_name.clone(), case_header_name);
    }

    Ok(value_map.append(header_name, value))
}

#[inline]
fn insert_header_value<T>(
    name_map: Option<&mut CaseMap>,
    value_map: &mut HMap<T>,
    name: impl IntoCaseHeaderName,
    value: T,
) -> Result<()> {
    let case_header_name = name.into_case_header_name();
    let header_name: HeaderName = case_header_name
        .as_slice()
        .try_into()
        .or_err(InvalidHTTPHeader, "invalid header name")?;
    if let Some(name_map) = name_map {
        // store the original case in the map
        name_map.insert(header_name.clone(), case_header_name);
    }
    value_map.insert(header_name, value);
    Ok(())
}

// the &N here is to avoid clone(). None Copy type like String can impl AsHeaderName
#[inline]
fn remove_header<'a, T, N: ?Sized>(
    name_map: Option<&mut CaseMap>,
    value_map: &mut HMap<T>,
    name: &'a N,
) -> Option<T>
where
    &'a N: 'a + AsHeaderName,
{
    if let Some(name_map) = name_map {
        name_map.remove(name);
    }
    value_map.remove(name)
}

// 使用 `#[inline]` 属性提示编译器在可能时内联此函数，以优化运行时性能。
#[inline]
fn header_to_h1_wire(
    key_map: Option<&CaseMap>, // 可选的 `CaseMap` 引用，用于映射头部字段名到其规范形式。
    value_map: &HMap,          // `HMap` 引用，存储头部字段及其值。
    buf: &mut impl BufMut,     // 输出缓冲区，实现 `BufMut` 特性，用于写入格式化的头部数据。
) {
    // 定义 HTTP 头部键值对之间的分隔符。
    const HEADER_KV_DELIMITER: &[u8; 2] = b": ";
    // 定义头部行的结束符号。
    const CRLF: &[u8; 2] = b"\r\n";

    // 检查是否提供了 `key_map`。
    if let Some(key_map) = key_map {
        // 如果存在 `key_map`，则获取键的迭代器并与值的迭代器进行配对。
        let iter = key_map.iter().zip(value_map.iter());
        for ((header, case_header), (header2, val)) in iter {
            // 确保迭代器中的键（来自两个不同的源）是相匹配的。
            if header != header2 {
                // 如果头部名称不匹配，则抛出异常，因为这可能意味着 `HMap` 实现的迭代顺序有变化。
                panic!("header iter mismatch {}, {}", header, header2)
            }
            // 将规范形式的头部名称写入缓冲区。
            buf.put_slice(case_header.as_slice());
            // 添加键值分隔符。
            buf.put_slice(HEADER_KV_DELIMITER);
            // 将头部值写入缓冲区。
            buf.put_slice(val.as_ref());
            // 添加行结束符号。
            buf.put_slice(CRLF);
        }
    } else {
        // 如果没有提供 `key_map`，则直接从 `value_map` 迭代。
        for (header, value) in value_map {
            // 尝试获取头部名称的标题化（首字母大写）形式。
            let titled_header =
                case_header_name::titled_header_name_str(header).unwrap_or(header.as_str());
            // 将标题化的头部名称写入缓冲区。
            buf.put_slice(titled_header.as_bytes());
            // 添加键值分隔符。
            buf.put_slice(HEADER_KV_DELIMITER);
            // 将头部值写入缓冲区。
            buf.put_slice(value.as_ref());
            // 添加行结束符号。
            buf.put_slice(CRLF);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_map_upper_bound() {
        assert_eq!(8, http_header_map_upper_bound(None));
        assert_eq!(16, http_header_map_upper_bound(Some(16)));
        assert_eq!(4096, http_header_map_upper_bound(Some(7777)));
    }

    #[test]
    fn test_single_header() {
        let mut req = RequestHeader::build("GET", b"\\", None).unwrap();
        req.insert_header("foo", "bar").unwrap();
        req.insert_header("FoO", "Bar").unwrap();
        let mut buf: Vec<u8> = vec![];
        req.header_to_h1_wire(&mut buf);
        assert_eq!(buf, b"FoO: Bar\r\n");

        let mut resp = ResponseHeader::new(None);
        req.insert_header("foo", "bar").unwrap();
        resp.insert_header("FoO", "Bar").unwrap();
        let mut buf: Vec<u8> = vec![];
        resp.header_to_h1_wire(&mut buf);
        assert_eq!(buf, b"FoO: Bar\r\n");
    }

    #[test]
    fn test_single_header_no_case() {
        let mut req = RequestHeader::new_no_case(None);
        req.insert_header("foo", "bar").unwrap();
        req.insert_header("FoO", "Bar").unwrap();
        let mut buf: Vec<u8> = vec![];
        req.header_to_h1_wire(&mut buf);
        assert_eq!(buf, b"foo: Bar\r\n");

        let mut resp = ResponseHeader::new_no_case(None);
        req.insert_header("foo", "bar").unwrap();
        resp.insert_header("FoO", "Bar").unwrap();
        let mut buf: Vec<u8> = vec![];
        resp.header_to_h1_wire(&mut buf);
        assert_eq!(buf, b"foo: Bar\r\n");
    }

    #[test]
    fn test_multiple_header() {
        let mut req = RequestHeader::build("GET", b"\\", None).unwrap();
        req.append_header("FoO", "Bar").unwrap();
        req.append_header("fOO", "bar").unwrap();
        req.append_header("BAZ", "baR").unwrap();
        req.append_header(http::header::CONTENT_LENGTH, "0")
            .unwrap();
        req.append_header("a", "b").unwrap();
        req.remove_header("a");
        let mut buf: Vec<u8> = vec![];
        req.header_to_h1_wire(&mut buf);
        assert_eq!(
            buf,
            b"FoO: Bar\r\nfOO: bar\r\nBAZ: baR\r\nContent-Length: 0\r\n"
        );

        let mut resp = ResponseHeader::new(None);
        resp.append_header("FoO", "Bar").unwrap();
        resp.append_header("fOO", "bar").unwrap();
        resp.append_header("BAZ", "baR").unwrap();
        resp.append_header(http::header::CONTENT_LENGTH, "0")
            .unwrap();
        resp.append_header("a", "b").unwrap();
        resp.remove_header("a");
        let mut buf: Vec<u8> = vec![];
        resp.header_to_h1_wire(&mut buf);
        assert_eq!(
            buf,
            b"FoO: Bar\r\nfOO: bar\r\nBAZ: baR\r\nContent-Length: 0\r\n"
        );
    }

    #[cfg(feature = "patched_http1")]
    #[test]
    fn test_invalid_path() {
        let raw_path = b"Hello\xF0\x90\x80World";
        let req = RequestHeader::build("GET", &raw_path[..], None).unwrap();
        assert_eq!("Hello�World", req.uri.path_and_query().unwrap());
        assert_eq!(raw_path, req.raw_path());
    }
}
