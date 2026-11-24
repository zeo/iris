// hide the console window on release builds; keep it in debug for logs
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    iris_app_lib::run();
}
