// Helper function to get relative path without borrowing self
/// `file_path` relative to `base_path`, or just `file_path`'s final path
/// component if it isn't under `base_path`.
pub fn get_relative_path(file_path: &str, base_path: &str) -> String {
    use std::path::Path;

    // Get the canonical paths to handle . and .. properly
    let base_path_obj = Path::new(base_path);
    let file_path_obj = Path::new(file_path);

    // Try to get the relative path from base to file
    if let Ok(relative) = file_path_obj.strip_prefix(base_path_obj) {
        relative.to_string_lossy().to_string()
    } else {
        // Fall back to just the filename if we can't get relative path
        file_path
            .split('/')
            .next_back()
            .unwrap_or(file_path)
            .to_string()
    }
}
