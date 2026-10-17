//! a live throughput graph drawn into the tray icon, the way a taskbar meter
//! shows traffic without opening the window. each engine tick adds a column:
//! download rises from the bottom, upload hangs from the top, both scaled to
//! the busiest moment still on screen.

use std::collections::VecDeque;
use std::sync::Mutex;
use tauri::Manager;

const SIZE: usize = 32;
const COLUMNS: usize = 15;
const COLUMN_WIDTH: usize = 2;
const INSET: usize = 1;
/// the scale never drops below this, so an idle link reads as idle instead of
/// a stray packet filling the icon
const FLOOR_BYTES_PER_SEC: u64 = 32 * 1024;

const PLATE: [u8; 4] = [22, 22, 22, 235];
const DOWN: [u8; 4] = [236, 236, 236, 255];
const UP: [u8; 4] = [140, 140, 140, 255];

pub struct TrayGraph {
    enabled: bool,
    history: VecDeque<(u64, u64)>,
    showing_graph: bool,
}

impl Default for TrayGraph {
    fn default() -> Self {
        TrayGraph {
            enabled: true,
            history: VecDeque::with_capacity(COLUMNS),
            showing_graph: false,
        }
    }
}

pub struct TrayGraphState(pub Mutex<TrayGraph>);

impl Default for TrayGraphState {
    fn default() -> Self {
        TrayGraphState(Mutex::new(TrayGraph::default()))
    }
}

/// add one tick's totals and redraw the tray
pub fn push(app: &tauri::AppHandle, down: u64, up: u64) {
    let Some(state) = app.try_state::<TrayGraphState>() else {
        return;
    };
    let mut graph = state.0.lock().unwrap_or_else(|error| error.into_inner());
    if graph.history.len() == COLUMNS {
        graph.history.pop_front();
    }
    graph.history.push_back((down, up));
    let Some(tray) = app.tray_by_id(crate::TRAY_ID) else {
        return;
    };
    let _ = tray.set_tooltip(Some(format!(
        "Iris\n↓ {}/s   ↑ {}/s",
        human(down),
        human(up)
    )));
    if graph.enabled {
        let pixels = render(&graph.history);
        let _ = tray.set_icon(Some(tauri::image::Image::new_owned(pixels, SIZE as u32, SIZE as u32)));
        graph.showing_graph = true;
    }
}

#[tauri::command]
pub fn set_tray_graph(app: tauri::AppHandle, state: tauri::State<'_, TrayGraphState>, enabled: bool) {
    let mut graph = state.0.lock().unwrap_or_else(|error| error.into_inner());
    graph.enabled = enabled;
    if !enabled && graph.showing_graph {
        graph.showing_graph = false;
        if let (Some(tray), Some(icon)) = (app.tray_by_id(crate::TRAY_ID), app.default_window_icon()) {
            let _ = tray.set_icon(Some(icon.clone()));
        }
    }
}

/// rgba pixels for the icon: a dark plate with one column per sample, newest
/// on the right
fn render(history: &VecDeque<(u64, u64)>) -> Vec<u8> {
    let mut pixels = vec![0u8; SIZE * SIZE * 4];
    let mut paint = |x: usize, y: usize, color: [u8; 4]| {
        let at = (y * SIZE + x) * 4;
        pixels[at..at + 4].copy_from_slice(&color);
    };
    for y in 0..SIZE {
        for x in 0..SIZE {
            // trim the corners for a rounded plate
            let edge = |v: usize| v.min(SIZE - 1 - v);
            if edge(x) + edge(y) >= 2 {
                paint(x, y, PLATE);
            }
        }
    }

    let peak = history
        .iter()
        .map(|(down, up)| (*down).max(*up))
        .max()
        .unwrap_or(0)
        .max(FLOOR_BYTES_PER_SEC);
    let span = SIZE - 2 * INSET;
    let half = span / 2;
    let height = |bytes: u64| -> usize {
        if bytes == 0 {
            return 0;
        }
        (((bytes as u128 * half as u128) / peak as u128) as usize).clamp(1, half)
    };
    let first = SIZE - INSET - history.len() * COLUMN_WIDTH;
    for (index, (down, up)) in history.iter().enumerate() {
        let left = first + index * COLUMN_WIDTH;
        for x in left..left + COLUMN_WIDTH {
            for step in 0..height(*down) {
                paint(x, SIZE - INSET - 1 - step, DOWN);
            }
            for step in 0..height(*up) {
                paint(x, INSET + step, UP);
            }
        }
    }
    pixels
}

fn human(bytes: u64) -> String {
    const UNITS: [&str; 4] = ["B", "KB", "MB", "GB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

#[cfg(test)]
mod tests {
    use super::{human, render, COLUMNS, SIZE};
    use std::collections::VecDeque;

    fn pixel(pixels: &[u8], x: usize, y: usize) -> [u8; 4] {
        let at = (y * SIZE + x) * 4;
        pixels[at..at + 4].try_into().unwrap()
    }

    #[test]
    fn download_rises_from_the_bottom_and_upload_hangs_from_the_top() {
        let history: VecDeque<_> = [(0, 0), (1_000_000, 250_000)].into_iter().collect();
        let pixels = render(&history);
        assert_eq!(pixels.len(), SIZE * SIZE * 4);
        let newest = SIZE - 2;
        assert_eq!(pixel(&pixels, newest, SIZE - 2), super::DOWN);
        assert_eq!(pixel(&pixels, newest, SIZE / 2 + 1), super::DOWN);
        assert_eq!(pixel(&pixels, newest, 1), super::UP);
        assert_eq!(pixel(&pixels, newest, 10), super::PLATE);
        assert_eq!(pixel(&pixels, newest - 2, SIZE - 2), super::PLATE);
        assert_eq!(pixel(&pixels, 0, 0)[3], 0);
    }

    #[test]
    fn a_full_history_fits_inside_the_plate() {
        let history: VecDeque<_> = (0..COLUMNS as u64).map(|n| (n * 10_000, n)).collect();
        assert_eq!(render(&history).len(), SIZE * SIZE * 4);
    }

    #[test]
    fn rates_read_in_binary_units() {
        assert_eq!(human(512), "512 B");
        assert_eq!(human(1536), "1.5 KB");
        assert_eq!(human(5 * 1024 * 1024), "5.0 MB");
    }
}
