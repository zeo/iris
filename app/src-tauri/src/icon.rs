//! extract an application's icon from its executable and return it as a PNG data
//! URI. runs in the unprivileged UI process. results are cached on the frontend,
//! so this is called at most once per distinct app path.

/// return a `data:image/png;base64,...` URI for the exe's icon, or None.
#[tauri::command]
pub fn app_icon(path: String) -> Option<String> {
    #[cfg(windows)]
    {
        let png = win::extract_png(&path)?;
        use base64::Engine;
        let b64 = base64::engine::general_purpose::STANDARD.encode(&png);
        Some(format!("data:image/png;base64,{b64}"))
    }
    #[cfg(target_os = "linux")]
    {
        linux::icon_data_uri(&path)
    }
    #[cfg(not(any(windows, target_os = "linux")))]
    {
        let _ = path;
        None
    }
}

#[cfg(target_os = "linux")]
pub(crate) mod linux {
    use std::path::{Path, PathBuf};

    /// resolve an executable to an icon and return it as a data URI. an app's icon
    /// lives in the icon theme, keyed by an icon name, not embedded in the binary,
    /// so we find the icon name (from the binary name or a matching .desktop file)
    /// and then the icon file, embedding a PNG or SVG. None when nothing matches;
    /// the UI then shows its generic mark.
    pub fn icon_data_uri(path: &str) -> Option<String> {
        let file = icon_path(path)?;
        let bytes = std::fs::read(&file).ok()?;
        let mime = match file.extension().and_then(|e| e.to_str()) {
            Some("svg") => "image/svg+xml",
            _ => "image/png",
        };
        use base64::Engine;
        let b64 = base64::engine::general_purpose::STANDARD.encode(&bytes);
        Some(format!("data:{mime};base64,{b64}"))
    }

    pub fn icon_path(path: &str) -> Option<PathBuf> {
        let stem = Path::new(path).file_name()?.to_str()?.to_string();
        let name = icon_name_for(path, &stem).unwrap_or(stem);
        find_icon_file(path, &name)
    }

    /// the Icon= value of the first .desktop file whose executable matches, so an
    /// app whose icon name differs from its binary name still resolves
    fn icon_name_for(path: &str, binary: &str) -> Option<String> {
        for dir in desktop_dirs(path) {
            let Ok(entries) = std::fs::read_dir(&dir) else {
                continue;
            };
            for entry in entries.flatten() {
                let p = entry.path();
                if p.extension().and_then(|e| e.to_str()) != Some("desktop") {
                    continue;
                }
                let Ok(text) = std::fs::read_to_string(&p) else {
                    continue;
                };
                if desktop_matches(&text, path, binary) {
                    if let Some(icon) = field(&text, "Icon") {
                        return Some(icon);
                    }
                }
            }
        }
        None
    }

    fn desktop_matches(text: &str, path: &str, binary: &str) -> bool {
        for key in ["Exec", "TryExec"] {
            if let Some(val) = field(text, key) {
                let first = val.split_whitespace().next().unwrap_or("");
                let base = Path::new(first)
                    .file_name()
                    .and_then(|s| s.to_str())
                    .unwrap_or(first);
                if base == binary {
                    return true;
                }
            }
        }
        let appimage = path
            .rsplit_once('.')
            .is_some_and(|(_, extension)| extension.eq_ignore_ascii_case("appimage"));
        if !appimage {
            return false;
        }
        let bundle = Path::new(binary)
            .file_stem()
            .and_then(|stem| stem.to_str())
            .map(normalized_identifier)
            .unwrap_or_default();
        ["Name", "StartupWMClass"]
            .into_iter()
            .filter_map(|key| field(text, key))
            .map(|identity| normalized_identifier(&identity))
            .any(|identity| identity.len() >= 4 && bundle.starts_with(&identity))
    }

    fn normalized_identifier(identity: &str) -> String {
        identity
            .chars()
            .filter(|character| character.is_alphanumeric())
            .flat_map(char::to_lowercase)
            .collect()
    }

    fn field(text: &str, key: &str) -> Option<String> {
        text.lines()
            .find_map(|l| l.strip_prefix(key).and_then(|r| r.strip_prefix('=')))
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
    }

    /// locate an icon file for a name: an absolute path as-is, else the largest
    /// available PNG in the icon theme, else an SVG, else a pixmap
    fn find_icon_file(path: &str, name: &str) -> Option<PathBuf> {
        if name.starts_with('/') {
            let p = PathBuf::from(name);
            return p.exists().then_some(p);
        }
        for base in icon_roots(path) {
            for size in ["256x256", "128x128", "96x96", "64x64", "48x48", "scalable"] {
                for ext in ["png", "svg"] {
                    let p = base
                        .join("hicolor")
                        .join(size)
                        .join("apps")
                        .join(format!("{name}.{ext}"));
                    if p.exists() {
                        return Some(p);
                    }
                }
            }
        }
        for ext in ["png", "svg", "xpm"] {
            let p = PathBuf::from(format!("/usr/share/pixmaps/{name}.{ext}"));
            if ext != "xpm" && p.exists() {
                return Some(p);
            }
        }
        None
    }

    fn icon_roots(path: &str) -> Vec<PathBuf> {
        let mut roots = Vec::new();
        if let Some(usr) = bundled_usr(path) {
            roots.push(usr.join("share/icons"));
        }
        if let Some(home) = std::env::var_os("HOME") {
            roots.push(PathBuf::from(&home).join(".local/share/icons"));
            roots.push(PathBuf::from(home).join(".icons"));
        }
        roots.push(PathBuf::from("/usr/local/share/icons"));
        roots.push(PathBuf::from("/usr/share/icons"));
        roots
    }

    fn desktop_dirs(path: &str) -> Vec<PathBuf> {
        let mut dirs = Vec::new();
        if let Some(usr) = bundled_usr(path) {
            dirs.push(usr.join("share/applications"));
        }
        if let Some(home) = std::env::var_os("HOME") {
            dirs.push(PathBuf::from(home).join(".local/share/applications"));
        }
        dirs.push(PathBuf::from("/usr/local/share/applications"));
        dirs.push(PathBuf::from("/usr/share/applications"));
        dirs
    }

    fn bundled_usr(path: &str) -> Option<PathBuf> {
        Path::new(path)
            .ancestors()
            .find(|ancestor| ancestor.file_name().and_then(|name| name.to_str()) == Some("usr"))
            .map(Path::to_path_buf)
    }

    #[cfg(test)]
    mod tests {
        use super::desktop_matches;

        #[test]
        fn matches_the_desktop_executable_directly() {
            let desktop = "Exec=/usr/bin/browser %U\nIcon=browser\n";
            assert!(desktop_matches(desktop, "/usr/bin/browser", "browser"));
        }

        #[test]
        fn matches_a_versioned_appimage_by_desktop_identity() {
            let desktop = "Name=Example\nExec=/home/user/.local/bin/example %U\nIcon=org.example.app\nStartupWMClass=example\n";
            assert!(desktop_matches(
                desktop,
                "/home/user/Downloads/example-1.0.0-x86_64.AppImage",
                "example-1.0.0-x86_64.AppImage"
            ));
        }

        #[test]
        fn does_not_fuzzy_match_an_ordinary_executable() {
            let desktop = "Name=Browser\nExec=/opt/other-browser\nIcon=browser\n";
            assert!(!desktop_matches(
                desktop,
                "/tmp/browser-nightly",
                "browser-nightly"
            ));
        }
    }
}

#[cfg(windows)]
mod win {
    use std::ffi::c_void;
    use std::io::Cursor;
    use std::mem::size_of;
    use windows::core::PCWSTR;
    use windows::Win32::Graphics::Gdi::{
        DeleteObject, GetDC, GetDIBits, GetObjectW, ReleaseDC, BITMAP, BITMAPINFO,
        BITMAPINFOHEADER, DIB_RGB_COLORS, HGDIOBJ,
    };
    use windows::Win32::UI::Shell::{SHGetFileInfoW, SHFILEINFOW, SHGFI_ICON, SHGFI_LARGEICON};
    use windows::Win32::UI::WindowsAndMessaging::{DestroyIcon, GetIconInfo, HICON, ICONINFO};

    pub fn extract_png(path: &str) -> Option<Vec<u8>> {
        unsafe {
            let wide: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();
            let mut info = SHFILEINFOW::default();
            let ok = SHGetFileInfoW(
                PCWSTR(wide.as_ptr()),
                Default::default(),
                Some(&mut info),
                size_of::<SHFILEINFOW>() as u32,
                SHGFI_ICON | SHGFI_LARGEICON,
            );
            if ok == 0 || info.hIcon.is_invalid() {
                return None;
            }
            let png = hicon_to_png(info.hIcon);
            let _ = DestroyIcon(info.hIcon);
            png
        }
    }

    unsafe fn hicon_to_png(hicon: HICON) -> Option<Vec<u8>> {
        let mut ii = ICONINFO::default();
        GetIconInfo(hicon, &mut ii).ok()?;

        let mut bmp = BITMAP::default();
        let got = GetObjectW(
            HGDIOBJ(ii.hbmColor.0),
            size_of::<BITMAP>() as i32,
            Some(&mut bmp as *mut _ as *mut c_void),
        );
        if got == 0 || bmp.bmWidth <= 0 || bmp.bmHeight <= 0 {
            let _ = DeleteObject(HGDIOBJ(ii.hbmColor.0));
            let _ = DeleteObject(HGDIOBJ(ii.hbmMask.0));
            return None;
        }
        let (w, h) = (bmp.bmWidth, bmp.bmHeight);

        let mut bi = BITMAPINFO::default();
        bi.bmiHeader.biSize = size_of::<BITMAPINFOHEADER>() as u32;
        bi.bmiHeader.biWidth = w;
        bi.bmiHeader.biHeight = -h; // top-down
        bi.bmiHeader.biPlanes = 1;
        bi.bmiHeader.biBitCount = 32;
        bi.bmiHeader.biCompression = 0; // BI_RGB

        let mut buf = vec![0u8; (w * h * 4) as usize];
        let hdc = GetDC(None);
        let lines = GetDIBits(
            hdc,
            ii.hbmColor,
            0,
            h as u32,
            Some(buf.as_mut_ptr() as *mut c_void),
            &mut bi,
            DIB_RGB_COLORS,
        );
        ReleaseDC(None, hdc);
        let _ = DeleteObject(HGDIOBJ(ii.hbmColor.0));
        let _ = DeleteObject(HGDIOBJ(ii.hbmMask.0));
        if lines == 0 {
            return None;
        }

        // GetDIBits gives BGRA. if the icon carried no alpha (legacy), make it
        // opaque; otherwise keep it.
        let has_alpha = buf.chunks_exact(4).any(|p| p[3] != 0);
        for px in buf.chunks_exact_mut(4) {
            px.swap(0, 2);
            if !has_alpha {
                px[3] = 255;
            }
        }

        let mut out = Vec::new();
        {
            let mut enc = png::Encoder::new(Cursor::new(&mut out), w as u32, h as u32);
            enc.set_color(png::ColorType::Rgba);
            enc.set_depth(png::BitDepth::Eight);
            let mut writer = enc.write_header().ok()?;
            writer.write_image_data(&buf).ok()?;
        }
        Some(out)
    }
}
