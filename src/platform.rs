/// 平台兼容性模块
/// 处理Windows、Linux、macOS等不同平台的特定功能

use std::net::IpAddr;
use crate::Result;

// 平台特定模块在文件内部定义

/// 跨平台网络接口信息
#[derive(Debug, Clone)]
pub struct NetworkInterface {
    pub name: String,
    pub ip: std::net::IpAddr,
    pub is_up: bool,
    pub is_loopback: bool,
}

/// 跨平台系统信息
#[derive(Debug)]
pub struct SystemInfo {
    pub os_name: String,
    pub os_version: String,
    pub architecture: String,
    pub hostname: String,
}

/// 获取所有网络接口
pub fn get_network_interfaces() -> Result<Vec<NetworkInterface>> {
    #[cfg(windows)]
    return windows::get_network_interfaces();
    
    #[cfg(unix)]
    return unix::get_network_interfaces();
    
    #[cfg(not(any(windows, unix)))]
    {
        use crate::ScanError;
        Err(ScanError::PlatformNotSupported("Network interface enumeration not supported on this platform".to_string()))
    }
}

/// 获取系统信息
pub fn get_system_info() -> Result<SystemInfo> {
    let hostname = hostname::get()
        .map_err(|e| crate::ScanError::SystemError(format!("Failed to get hostname: {}", e)))?
        .to_string_lossy()
        .to_string();

    Ok(SystemInfo {
        os_name: std::env::consts::OS.to_string(),
        os_version: get_os_version()?,
        architecture: std::env::consts::ARCH.to_string(),
        hostname,
    })
}

/// 检查是否具有管理员/root权限
pub fn has_admin_privileges() -> bool {
    #[cfg(windows)]
    {
        use windows_sys::Win32::Security::{GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY};
        use windows_sys::Win32::System::Threading::GetCurrentProcess;
        use windows_sys::Win32::Foundation::{GetLastError, CloseHandle, HANDLE, TRUE};
        use windows_sys::Win32::Security::OpenProcessToken;
        
        unsafe {
            let mut token: HANDLE = 0;
            if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
                return false;
            }
            
            let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
            let mut return_length = 0u32;
            
            let result = GetTokenInformation(
                token,
                TokenElevation,
                &mut elevation as *mut _ as *mut _,
                std::mem::size_of::<TOKEN_ELEVATION>() as u32,
                &mut return_length
            );
            
            CloseHandle(token);
            
            if result == 0 {
                false
            } else {
                elevation.TokenIsElevated != 0
            }
        }
    }
    
    #[cfg(unix)]
    {
        unsafe {
            libc::geteuid() == 0
        }
    }
}

/// 检查是否可以创建原始套接字
pub fn can_create_raw_socket() -> bool {
    #[cfg(windows)]
    {
        // 在Windows上，原始套接字需要管理员权限
        has_admin_privileges()
    }
    
    #[cfg(unix)]
    {
        // 在Unix系统上，尝试创建一个原始套接字
        use std::os::unix::io::AsRawFd;
        use socket2::{Socket, Domain, Type, Protocol};
        
        match Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4)) {
            Ok(_) => true,
            Err(_) => false,
        }
    }
}

/// 设置进程优先级
pub fn set_process_priority(priority: ProcessPriority) -> Result<()> {
    #[cfg(windows)]
    return windows::set_process_priority(priority);
    
    #[cfg(unix)]
    return unix::set_process_priority(priority);
    
    #[cfg(not(any(windows, unix)))]
    {
        use crate::ScanError;
        Err(ScanError::PlatformNotSupported("Process priority setting not supported on this platform".to_string()))
    }
}

/// 进程优先级枚举
#[derive(Debug, Clone, Copy)]
pub enum ProcessPriority {
    Low,
    Normal,
    High,
    Realtime,
}

/// 获取操作系统版本
fn get_os_version() -> Result<String> {
    #[cfg(windows)]
    {
        use winapi::um::winnt::OSVERSIONINFOW;
        use winapi::um::sysinfoapi::GetVersionExW;
        use std::mem;
        
        unsafe {
            let mut version_info: OSVERSIONINFOW = mem::zeroed();
            version_info.dwOSVersionInfoSize = mem::size_of::<OSVERSIONINFOW>() as u32;
            
            if GetVersionExW(&mut version_info) != 0 {
                Ok(format!("{}.{}.{}", 
                    version_info.dwMajorVersion,
                    version_info.dwMinorVersion,
                    version_info.dwBuildNumber
                ))
            } else {
                Ok("Unknown".to_string())
            }
        }
    }
    
    #[cfg(target_os = "linux")]
    {
        use std::fs;
        match fs::read_to_string("/proc/version") {
            Ok(content) => Ok(content.lines().next().unwrap_or("Unknown").to_string()),
            Err(_) => Ok("Unknown".to_string()),
        }
    }
    
    #[cfg(target_os = "macos")]
    {
        use std::process::Command;
        match Command::new("sw_vers").arg("-productVersion").output() {
            Ok(output) => Ok(String::from_utf8_lossy(&output.stdout).trim().to_string()),
            Err(_) => Ok("Unknown".to_string()),
        }
    }
    
    #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
    {
        Ok("Unknown".to_string())
    }
}

/// 平台特定的错误消息转换
pub fn platform_error_message(error: &str) -> String {
    #[cfg(windows)]
    {
        // 在Windows上，某些错误需要特殊处理
        if error.contains("Access is denied") {
            return "需要管理员权限。请以管理员身份运行程序。".to_string();
        }
        if error.contains("No such host") {
            return "无法解析主机名。请检查网络连接和DNS设置。".to_string();
        }
    }
    
    #[cfg(unix)]
    {
        // 在Unix系统上的错误处理
        if error.contains("Permission denied") {
            return "权限不足。请使用sudo运行程序或检查文件权限。".to_string();
        }
        if error.contains("Name or service not known") {
            return "无法解析主机名。请检查网络连接和DNS设置。".to_string();
        }
    }
    
    error.to_string()
}

// 添加hostname依赖
use hostname;

/// Windows特定功能模块
#[cfg(windows)]
mod windows {
    use super::*;
    use std::net::IpAddr;
    use winapi::um::winnt::*;
    use winapi::um::processthreadsapi::*;
    use winapi::um::handleapi::*;
    use winapi::um::securitybaseapi::*;
    use winapi::um::iphlpapi::*;
    use crate::{Result, ScanError};
    
    pub fn get_network_interfaces() -> Result<Vec<NetworkInterface>> {
        use if_addrs;
        
        let addrs = if_addrs::get_if_addrs()
            .map_err(|e| ScanError::SystemError(format!("Failed to get network interfaces: {}", e)))?;
        
        let mut interfaces = std::collections::HashMap::new();
        
        for addr in addrs {
            let entry = interfaces.entry(addr.name.clone()).or_insert_with(|| NetworkInterface {
                name: addr.name.clone(),
                ip: addr.ip(),
                is_up: !addr.is_loopback(),
                is_loopback: addr.is_loopback(),
            });
        }
        
        Ok(interfaces.into_values().collect())
    }
    
    pub fn has_admin_privileges() -> bool {
        use std::ptr;
        
        unsafe {
            let mut token = ptr::null_mut();
            if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
                return false;
            }
            
            let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
            let mut return_length = 0u32;
            
            let result = GetTokenInformation(
                token,
                TokenElevation,
                &mut elevation as *mut _ as *mut _,
                std::mem::size_of::<TOKEN_ELEVATION>() as u32,
                &mut return_length,
            );
            
            CloseHandle(token);
            
            result != 0 && elevation.TokenIsElevated != 0
        }
    }
    
    pub fn set_process_priority(priority: ProcessPriority) -> Result<()> {
        use winapi::um::winbase::*;
        
        let priority_class = match priority {
            ProcessPriority::Low => IDLE_PRIORITY_CLASS,
            ProcessPriority::Normal => NORMAL_PRIORITY_CLASS,
            ProcessPriority::High => HIGH_PRIORITY_CLASS,
            ProcessPriority::Realtime => REALTIME_PRIORITY_CLASS,
        };
        
        unsafe {
            if SetPriorityClass(GetCurrentProcess(), priority_class) == 0 {
                return Err(ScanError::SystemError("Failed to set process priority".to_string()));
            }
        }
        
        Ok(())
    }
}

/// Unix特定功能模块（Linux、macOS等）
#[cfg(unix)]
mod unix {
    use super::*;
    use std::net::IpAddr;
    use crate::{Result, ScanError};
    
    pub fn get_network_interfaces() -> Result<Vec<NetworkInterface>> {
        use if_addrs;
        
        let addrs = if_addrs::get_if_addrs()
            .map_err(|e| ScanError::SystemError(format!("Failed to get network interfaces: {}", e)))?;
        
        let mut interfaces = std::collections::HashMap::new();
        
        for addr in addrs {
            let entry = interfaces.entry(addr.name.clone()).or_insert_with(|| NetworkInterface {
                name: addr.name.clone(),
                ip: addr.ip(),
                is_up: !addr.is_loopback(),
                is_loopback: addr.is_loopback(),
            });
        }
        
        Ok(interfaces.into_values().collect())
    }
    
    pub fn has_admin_privileges() -> bool {
        unsafe { libc::geteuid() == 0 }
    }
    
    pub fn set_process_priority(priority: ProcessPriority) -> Result<()> {
        let nice_value = match priority {
            ProcessPriority::Low => 10,
            ProcessPriority::Normal => 0,
            ProcessPriority::High => -10,
            ProcessPriority::Realtime => -20,
        };
        
        unsafe {
            if libc::setpriority(libc::PRIO_PROCESS, 0, nice_value) != 0 {
                return Err(ScanError::SystemError("Failed to set process priority".to_string()));
            }
        }
        
        Ok(())
    }
} 