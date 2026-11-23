//! Navigation history and workspace roots.

use std::path::{Path, PathBuf};

pub const GTA_ROOT_LABEL: &str = "GTA VI";

/// Back/forward history of visited directories.
#[derive(Debug, Default)]
pub struct History {
    entries: Vec<PathBuf>,
    index: usize,
}

impl History {
    pub fn current(&self) -> Option<&Path> {
        self.entries.get(self.index).map(PathBuf::as_path)
    }

    /// Visits `path`, dropping any forward entries.
    pub fn push(&mut self, path: PathBuf) {
        if self.current() == Some(path.as_path()) {
            return;
        }
        if !self.entries.is_empty() {
            self.entries.truncate(self.index + 1);
            self.index += 1;
        }
        self.entries.push(path);
    }

    pub fn can_go_back(&self) -> bool {
        self.index > 0
    }

    pub fn can_go_forward(&self) -> bool {
        self.index + 1 < self.entries.len()
    }

    pub fn back(&mut self) -> Option<&Path> {
        if !self.can_go_back() {
            return None;
        }
        self.index -= 1;
        self.current()
    }

    pub fn forward(&mut self) -> Option<&Path> {
        if !self.can_go_forward() {
            return None;
        }
        self.index += 1;
        self.current()
    }

    /// Removes entries rejected by `keep`. If the current entry is removed, the
    /// closest earlier entry becomes current.
    pub fn retain(&mut self, keep: impl Fn(&Path) -> bool) {
        let mut entries: Vec<PathBuf> = Vec::new();
        let mut index = 0;
        for (i, path) in self.entries.drain(..).enumerate() {
            if !keep(&path) || entries.last() == Some(&path) {
                continue;
            }
            if i <= self.index {
                index = entries.len();
            }
            entries.push(path);
        }
        self.entries = entries;
        self.index = index;
    }
}

/// The GTA VI root and any additional folders opened by the user.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct Workspace {
    pub gta: Option<PathBuf>,
    pub folders: Vec<PathBuf>,
}

impl Workspace {
    /// Configured root paths, GTA VI first.
    pub fn root_paths(&self) -> impl Iterator<Item = &Path> {
        self.gta.iter().chain(&self.folders).map(PathBuf::as_path)
    }

    /// Adds a folder root. Returns `false` if it is already a root.
    pub fn add_folder(&mut self, path: PathBuf) -> bool {
        if self.root_paths().any(|root| root == path) {
            return false;
        }
        self.folders.push(path);
        true
    }

    pub fn remove_folder(&mut self, path: &Path) {
        self.folders.retain(|folder| folder != path);
    }

    /// The root containing `path`. Nested roots resolve to the innermost one.
    pub fn root_of(&self, path: &Path) -> Option<&Path> {
        self.root_paths()
            .filter(|root| path.starts_with(root))
            .max_by_key(|root| root.components().count())
    }

    pub fn is_folder_root(&self, path: &Path) -> bool {
        self.folders.iter().any(|folder| folder == path)
    }

    pub fn root_label(&self, root: &Path) -> String {
        if self.gta.as_deref() == Some(root) {
            return GTA_ROOT_LABEL.to_string();
        }
        folder_label(root)
    }

    /// Breadcrumb segments from the containing root down to `path`.
    pub fn breadcrumbs(&self, path: &Path) -> Vec<(String, PathBuf)> {
        let Some(root) = self.root_of(path) else {
            return Vec::new();
        };
        let mut crumbs = vec![(self.root_label(root), root.to_path_buf())];
        let mut current = root.to_path_buf();
        if let Ok(relative) = path.strip_prefix(root) {
            for component in relative.components() {
                current.push(component);
                crumbs.push((
                    component.as_os_str().to_string_lossy().into_owned(),
                    current.clone(),
                ));
            }
        }
        crumbs
    }

    /// The parent of `path`, unless `path` is a root.
    pub fn parent_within_root(&self, path: &Path) -> Option<PathBuf> {
        let root = self.root_of(path)?;
        if root == path {
            return None;
        }
        path.parent().map(Path::to_path_buf)
    }

    /// `path` and its ancestors up to and including its root, root first.
    pub fn ancestors_within_root(&self, path: &Path) -> Vec<PathBuf> {
        let Some(root) = self.root_of(path) else {
            return Vec::new();
        };
        let mut chain: Vec<PathBuf> = path
            .ancestors()
            .take_while(|ancestor| ancestor.starts_with(root))
            .map(Path::to_path_buf)
            .collect();
        chain.reverse();
        chain
    }
}

/// The label of a folder root: its name, or the full path for drive roots.
pub fn folder_label(path: &Path) -> String {
    path.file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.display().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(path: &str) -> PathBuf {
        PathBuf::from(path)
    }

    #[test]
    fn history_moves_back_and_forward() {
        let mut history = History::default();
        assert_eq!(history.current(), None);
        assert!(!history.can_go_back());

        history.push(p("a"));
        history.push(p("b"));
        history.push(p("c"));
        assert_eq!(history.back(), Some(p("b").as_path()));
        assert_eq!(history.back(), Some(p("a").as_path()));
        assert_eq!(history.back(), None);
        assert_eq!(history.forward(), Some(p("b").as_path()));
        assert!(history.can_go_forward());
    }

    #[test]
    fn pushing_drops_forward_entries_and_ignores_repeats() {
        let mut history = History::default();
        history.push(p("a"));
        history.push(p("b"));
        history.back();
        history.push(p("c"));
        history.push(p("c"));
        assert!(!history.can_go_forward());
        assert_eq!(history.back(), Some(p("a").as_path()));
        assert_eq!(history.back(), None);
    }

    #[test]
    fn retain_moves_to_closest_earlier_entry() {
        let mut history = History::default();
        for path in ["a", "x/1", "b", "x/2", "c"] {
            history.push(p(path));
        }
        history.back();
        assert_eq!(history.current(), Some(p("x/2").as_path()));

        history.retain(|path| !path.starts_with("x"));
        assert_eq!(history.current(), Some(p("b").as_path()));
        assert_eq!(history.forward(), Some(p("c").as_path()));
        assert_eq!(history.back(), Some(p("b").as_path()));
        assert_eq!(history.back(), Some(p("a").as_path()));
    }

    #[test]
    fn retain_merges_entries_that_become_adjacent() {
        let mut history = History::default();
        for path in ["a", "x", "a"] {
            history.push(p(path));
        }
        history.retain(|path| path != Path::new("x"));
        assert_eq!(history.current(), Some(p("a").as_path()));
        assert!(!history.can_go_back());
    }

    #[test]
    fn retain_can_empty_history() {
        let mut history = History::default();
        history.push(p("x"));
        history.retain(|_| false);
        assert_eq!(history.current(), None);
        history.push(p("a"));
        assert_eq!(history.current(), Some(p("a").as_path()));
    }

    fn workspace() -> Workspace {
        Workspace {
            gta: Some(p(r"D:\Games\GTA VI")),
            folders: vec![p(r"E:\Mods"), p(r"D:\Games\GTA VI\mods")],
        }
    }

    #[test]
    fn folders_are_added_once() {
        let mut workspace = workspace();
        assert!(!workspace.add_folder(p(r"E:\Mods")));
        assert!(!workspace.add_folder(p(r"D:\Games\GTA VI")));
        assert!(workspace.add_folder(p(r"F:\Research")));
        workspace.remove_folder(Path::new(r"E:\Mods"));
        assert_eq!(
            workspace.folders,
            [p(r"D:\Games\GTA VI\mods"), p(r"F:\Research")]
        );
        assert_eq!(workspace.gta, Some(p(r"D:\Games\GTA VI")));
    }

    #[test]
    fn resolves_innermost_root() {
        let workspace = workspace();
        assert_eq!(
            workspace.root_of(Path::new(r"D:\Games\GTA VI\x64\models")),
            Some(Path::new(r"D:\Games\GTA VI"))
        );
        assert_eq!(
            workspace.root_of(Path::new(r"D:\Games\GTA VI\mods\cars")),
            Some(Path::new(r"D:\Games\GTA VI\mods"))
        );
        assert_eq!(workspace.root_of(Path::new(r"D:\Games\GTA")), None);
        assert_eq!(workspace.root_of(Path::new(r"C:\Windows")), None);
    }

    #[test]
    fn builds_breadcrumbs_from_root() {
        let workspace = workspace();
        let crumbs = workspace.breadcrumbs(Path::new(r"D:\Games\GTA VI\x64\models"));
        let labels: Vec<_> = crumbs.iter().map(|(label, _)| label.as_str()).collect();
        assert_eq!(labels, ["GTA VI", "x64", "models"]);
        assert_eq!(crumbs[1].1, p(r"D:\Games\GTA VI\x64"));

        let crumbs = workspace.breadcrumbs(Path::new(r"E:\Mods"));
        assert_eq!(crumbs, [("Mods".to_string(), p(r"E:\Mods"))]);
        assert!(workspace.breadcrumbs(Path::new(r"C:\Windows")).is_empty());
    }

    #[test]
    fn up_stops_at_the_root() {
        let workspace = workspace();
        assert_eq!(
            workspace.parent_within_root(Path::new(r"E:\Mods\cars")),
            Some(p(r"E:\Mods"))
        );
        assert_eq!(workspace.parent_within_root(Path::new(r"E:\Mods")), None);
    }

    #[test]
    fn lists_ancestors_within_root() {
        let workspace = workspace();
        assert_eq!(
            workspace.ancestors_within_root(Path::new(r"E:\Mods\a\b")),
            [p(r"E:\Mods"), p(r"E:\Mods\a"), p(r"E:\Mods\a\b")]
        );
    }

    #[test]
    fn navigates_into_and_out_of_archives() {
        let workspace = workspace();
        let inside = p(r"D:\Games\GTA VI\data.rpf\Recovered Entries\XML");
        let labels: Vec<_> = workspace
            .breadcrumbs(&inside)
            .into_iter()
            .map(|(label, _)| label)
            .collect();
        assert_eq!(labels, ["GTA VI", "data.rpf", "Recovered Entries", "XML"]);
        assert_eq!(
            workspace.parent_within_root(&inside),
            Some(p(r"D:\Games\GTA VI\data.rpf\Recovered Entries"))
        );
        assert_eq!(
            workspace.ancestors_within_root(&inside)[1],
            p(r"D:\Games\GTA VI\data.rpf")
        );

        let mut history = History::default();
        history.push(p(r"D:\Games\GTA VI"));
        history.push(p(r"D:\Games\GTA VI\data.rpf"));
        history.push(inside.clone());
        assert_eq!(
            history.back(),
            Some(p(r"D:\Games\GTA VI\data.rpf").as_path())
        );
        assert_eq!(history.back(), Some(p(r"D:\Games\GTA VI").as_path()));
        assert_eq!(
            history.forward(),
            Some(p(r"D:\Games\GTA VI\data.rpf").as_path())
        );
        assert_eq!(history.forward(), Some(inside.as_path()));
    }

    #[test]
    fn labels_roots() {
        let workspace = workspace();
        assert_eq!(
            workspace.root_label(Path::new(r"D:\Games\GTA VI")),
            "GTA VI"
        );
        assert_eq!(workspace.root_label(Path::new(r"E:\Mods")), "Mods");
        assert_eq!(folder_label(Path::new(r"F:\")), r"F:\");
        assert_eq!(folder_label(Path::new(r"E:\Mod-Ordner ä")), "Mod-Ordner ä");
    }
}
