use std::env;

fn main() {
    // 设置构建配置
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=TARGET");
    
    let target = env::var("TARGET").unwrap();
    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap();
    
    // Windows特定配置
    if target_os == "windows" {
        println!("cargo:rustc-link-lib=ws2_32");
        println!("cargo:rustc-link-lib=iphlpapi");
        println!("cargo:rustc-link-lib=userenv");
        println!("cargo:rustc-link-lib=ntdll");
        
        // 尝试添加Windows资源文件（如果winres可用）
        #[cfg(windows)]
        {
            if let Ok(_) = winres::WindowsResource::new()
                .set_language(0x0409) // English (US)
                .compile() {
                // 资源文件编译成功
            }
        }
    }
    
    // Linux特定配置
    if target_os == "linux" {
        // 检查是否有pkg-config（仅在构建时检查）
        if std::process::Command::new("pkg-config")
            .arg("--exists")
            .arg("openssl")
            .output()
            .map(|output| output.status.success())
            .unwrap_or(false)
        {
            println!("cargo:rustc-cfg=has_openssl");
        }
        
        // 链接必要的系统库
        println!("cargo:rustc-link-lib=pthread");
    }
    
    // macOS特定配置
    if target_os == "macos" {
        println!("cargo:rustc-link-lib=framework=Foundation");
        println!("cargo:rustc-link-lib=framework=SystemConfiguration");
        println!("cargo:rustc-link-lib=framework=CoreFoundation");
    }
    
    // 交叉编译支持
    match target.as_str() {
        "x86_64-pc-windows-gnu" => {
            println!("cargo:rustc-link-lib=static=winpthread");
        },
        "i686-pc-windows-gnu" => {
            println!("cargo:rustc-link-lib=static=winpthread");
        },
        "x86_64-pc-windows-msvc" => {
            // MSVC specific settings
        },
        "i686-pc-windows-msvc" => {
            // MSVC specific settings
        },
        _ => {}
    }
    
    // 设置编译器特定标志
    if env::var("CARGO_CFG_TARGET_ENV").unwrap_or_default() == "msvc" {
        println!("cargo:rustc-cfg=msvc");
    }
    
    // 设置特性标志
    println!("cargo:rustc-cfg=build_time_detection");
    
    // 根据平台设置不同的特性
    match target_os.as_str() {
        "windows" => {
            println!("cargo:rustc-cfg=target_windows");
        },
        "linux" => {
            println!("cargo:rustc-cfg=target_linux");
        },
        "macos" => {
            println!("cargo:rustc-cfg=target_macos");
        },
        _ => {}
    }
} 