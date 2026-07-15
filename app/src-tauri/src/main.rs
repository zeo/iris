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
    let Some((gdk_scale, dpi_scale)) = fractional_gdk_scale(dpi) else {
        return;
    };
    std::env::set_var("GDK_BACKEND", "x11");
    std::env::set_var("GDK_SCALE", gdk_scale.to_string());
    std::env::set_var("GDK_DPI_SCALE", format!("{dpi_scale:.4}"));
}

#[cfg(target_os = "linux")]
fn fractional_gdk_scale(dpi: f64) -> Option<(u32, f64)> {
    let display_scale = dpi / 96.0;
    if !display_scale.is_finite() || !(1.0..=4.0).contains(&display_scale) {
        return None;
    }
    let nearest = display_scale.round();
    if (display_scale - nearest).abs() < 0.01 {
        return None;
    }
    let gdk_scale = display_scale.ceil() as u32;
    Some((gdk_scale, display_scale / f64::from(gdk_scale)))
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::fractional_gdk_scale;

    #[test]
    fn maps_fractional_dpi_to_an_integer_gtk_scale() {
        let (scale, dpi_scale) = fractional_gdk_scale(144.0).unwrap();
        assert_eq!(scale, 2);
        assert!((dpi_scale - 0.75).abs() < f64::EPSILON);
    }

    #[test]
    fn leaves_integer_and_invalid_scales_native() {
        assert!(fractional_gdk_scale(96.0).is_none());
        assert!(fractional_gdk_scale(192.0).is_none());
        assert!(fractional_gdk_scale(0.0).is_none());
    }
}
