// hide the console window on release builds; keep it in debug for logs
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    #[cfg(target_os = "linux")]
    configure_linux_display();
    iris_app_lib::run();
}

#[cfg(target_os = "linux")]
fn configure_linux_display() {
    if std::env::var_os("GDK_BACKEND").is_some()
        || std::env::var_os("GDK_SCALE").is_some()
        || std::env::var_os("GDK_DPI_SCALE").is_some()
        || std::env::var_os("WINIT_X11_SCALE_FACTOR").is_some()
        || std::env::var_os("DISPLAY").is_none()
        || std::env::var("XDG_SESSION_TYPE").as_deref() != Ok("wayland")
    {
        return;
    }
    let Ok(resources) = std::process::Command::new("xrdb").arg("-query").output() else {
        return;
    };
    let Some(dpi) = String::from_utf8_lossy(&resources.stdout)
        .lines()
        .find_map(|line| {
            line.strip_prefix("Xft.dpi:")
                .and_then(|dpi| dpi.trim().parse().ok())
        })
    else {
        return;
    };
    if !needs_x11_fallback(dpi) {
        return;
    }
    std::env::set_var("GDK_BACKEND", "x11");
    std::env::set_var("GDK_SCALE", "1");
    std::env::set_var("GDK_DPI_SCALE", "1");
    std::env::set_var("WINIT_X11_SCALE_FACTOR", "1");
    std::env::set_var("IRIS_X11_WEBVIEW_SCALE", format!("{:.4}", dpi / 96.0));
}

#[cfg(target_os = "linux")]
fn needs_x11_fallback(dpi: f64) -> bool {
    let display_scale = dpi / 96.0;
    if !display_scale.is_finite() || !(1.0..=4.0).contains(&display_scale) {
        return false;
    }
    let nearest = display_scale.round();
    (display_scale - nearest).abs() >= 0.01
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::needs_x11_fallback;

    #[test]
    fn uses_x11_for_fractional_wayland_scaling() {
        assert!(needs_x11_fallback(120.0));
        assert!(needs_x11_fallback(144.0));
        assert!(needs_x11_fallback(168.0));
    }

    #[test]
    fn leaves_integer_and_invalid_scales_native() {
        assert!(!needs_x11_fallback(96.0));
        assert!(!needs_x11_fallback(192.0));
        assert!(!needs_x11_fallback(0.0));
    }
}
