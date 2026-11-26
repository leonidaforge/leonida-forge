//! A byte-bounded cache for decoded images.

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;

use super::Image;

/// A least-recently-used cache bounded by the pixel bytes it holds.
///
/// A single image larger than the limit is returned to the caller but not
/// kept, so one huge texture cannot flush every smaller entry.
pub struct ImageCache {
    limit: usize,
    bytes: usize,
    entries: HashMap<(u32, u32), Arc<Image>>,
    order: VecDeque<(u32, u32)>,
}

impl ImageCache {
    pub fn new(limit: usize) -> Self {
        Self {
            limit,
            bytes: 0,
            entries: HashMap::new(),
            order: VecDeque::new(),
        }
    }

    pub fn limit(&self) -> usize {
        self.limit
    }

    pub fn bytes(&self) -> usize {
        self.bytes
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn get(&mut self, index: u32, level: u32) -> Option<Arc<Image>> {
        let key = (index, level);
        let image = self.entries.get(&key).cloned()?;
        self.touch(key);
        Some(image)
    }

    pub fn insert(&mut self, index: u32, level: u32, image: Arc<Image>) {
        let key = (index, level);
        let size = image.rgba.len();
        if size > self.limit {
            return;
        }
        if let Some(previous) = self.entries.remove(&key) {
            self.bytes = self.bytes.saturating_sub(previous.rgba.len());
        }
        self.order.retain(|entry| *entry != key);
        self.bytes += size;
        self.entries.insert(key, image);
        self.order.push_back(key);
        while self.bytes > self.limit {
            let Some(oldest) = self.order.pop_front() else {
                break;
            };
            if let Some(removed) = self.entries.remove(&oldest) {
                self.bytes = self.bytes.saturating_sub(removed.rgba.len());
            }
        }
    }

    pub fn clear(&mut self) {
        self.entries.clear();
        self.order.clear();
        self.bytes = 0;
    }

    fn touch(&mut self, key: (u32, u32)) {
        self.order.retain(|entry| *entry != key);
        self.order.push_back(key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn image(len: usize) -> Arc<Image> {
        Arc::new(Image {
            width: 1,
            height: 1,
            level: 0,
            rgba: vec![0; len],
        })
    }

    #[test]
    fn evicts_the_least_recently_used_entry() {
        let mut cache = ImageCache::new(12);
        cache.insert(0, 0, image(4));
        cache.insert(1, 0, image(4));
        cache.insert(2, 0, image(4));
        assert_eq!(cache.len(), 3);
        // Touch 0 so 1 becomes the oldest.
        assert!(cache.get(0, 0).is_some());
        cache.insert(3, 0, image(4));
        assert!(cache.get(1, 0).is_none());
        assert!(cache.get(0, 0).is_some());
        assert!(cache.get(3, 0).is_some());
        assert_eq!(cache.bytes(), 12);
    }

    #[test]
    fn an_oversized_image_is_not_kept() {
        let mut cache = ImageCache::new(4);
        cache.insert(0, 0, image(8));
        assert!(cache.get(0, 0).is_none());
        assert_eq!(cache.bytes(), 0);
    }

    #[test]
    fn replacing_an_entry_does_not_double_count() {
        let mut cache = ImageCache::new(16);
        cache.insert(0, 0, image(4));
        cache.insert(0, 0, image(8));
        assert_eq!(cache.len(), 1);
        assert_eq!(cache.bytes(), 8);
    }
}
