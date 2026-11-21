use std::path::Path;

fn main() {
    ceri_build::embed("../dist");
    ceri_build::resources(ceri_build::Resources {
        icon: Some(Path::new("icons/icon.ico")),
        product_name: Some("Iris"),
        copyright: Some("© rot"),
        ..Default::default()
    });
}
