//! File type names, icons and thumbnails from the Windows Shell.
//!
//! Windows is asked first. When it does not know a file type, these functions
//! return `None` and callers use their own names and icons.

use std::io;
use std::path::PathBuf;
use std::sync::mpsc;
use std::thread;

use futures::channel::oneshot;

use super::Entry;

/// A top-down BGRA bitmap with straight alpha.
pub struct Bitmap {
    pub width: u32,
    pub height: u32,
    pub pixels: Vec<u8>,
}

pub struct FileIcon {
    pub small: Bitmap,
    pub large: Bitmap,
}

/// The name Windows uses for the entry's type, e.g. "PNG File".
pub fn type_name(entry: &Entry) -> Option<String> {
    imp::type_name(entry)
}

enum Job {
    Icon {
        extension: String,
        reply: oneshot::Sender<Option<FileIcon>>,
    },
    Thumbnail {
        path: PathBuf,
        size: u32,
        reply: oneshot::Sender<Option<Bitmap>>,
    },
}

/// Runs icon and thumbnail requests on one thread in a single-threaded COM
/// apartment, which some thumbnail providers require.
pub struct ShellWorker {
    jobs: mpsc::Sender<Job>,
}

impl ShellWorker {
    pub fn start() -> io::Result<Self> {
        let (jobs, receiver) = mpsc::channel();
        thread::Builder::new().name("shell".into()).spawn(move || {
            imp::init_thread();
            for job in receiver {
                // A dropped receiver only means the answer is no longer needed.
                match job {
                    Job::Icon { extension, reply } => {
                        let _ = reply.send(imp::file_icon(&extension));
                    }
                    Job::Thumbnail { path, size, reply } => {
                        let _ = reply.send(imp::thumbnail(&path, size));
                    }
                }
            }
        })?;
        Ok(Self { jobs })
    }

    /// The icon Windows shows for files with `extension`.
    pub fn icon(&self, extension: String) -> oneshot::Receiver<Option<FileIcon>> {
        let (reply, receiver) = oneshot::channel();
        // If the worker is gone, the dropped sender cancels the receiver.
        let _ = self.jobs.send(Job::Icon { extension, reply });
        receiver
    }

    /// A thumbnail of at least `size` pixels, if a thumbnail provider can
    /// render the file.
    pub fn thumbnail(&self, path: PathBuf, size: u32) -> oneshot::Receiver<Option<Bitmap>> {
        let (reply, receiver) = oneshot::channel();
        let _ = self.jobs.send(Job::Thumbnail { path, size, reply });
        receiver
    }
}

#[cfg(windows)]
mod imp {
    use std::collections::HashMap;
    use std::ffi::c_void;
    use std::path::Path;
    use std::sync::{LazyLock, Mutex};

    use windows::Win32::Foundation::SIZE;
    use windows::Win32::Graphics::Gdi::{
        BI_RGB, BITMAP, BITMAPINFO, BITMAPINFOHEADER, CreateCompatibleDC, DIB_RGB_COLORS, DeleteDC,
        DeleteObject, GetDIBits, GetObjectW, HBITMAP,
    };
    use windows::Win32::Storage::FileSystem::{FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_NORMAL};
    use windows::Win32::System::Com::{
        COINIT_APARTMENTTHREADED, COINIT_DISABLE_OLE1DDE, COINIT_MULTITHREADED, CoInitializeEx,
    };
    use windows::Win32::System::Registry::{
        HKEY, HKEY_CLASSES_ROOT, KEY_READ, RegCloseKey, RegOpenKeyExW,
    };
    use windows::Win32::UI::Controls::{IImageList, ILD_TRANSPARENT};
    use windows::Win32::UI::Shell::{
        ASSOCF_INIT_IGNOREUNKNOWN, ASSOCSTR_FRIENDLYDOCNAME, AssocQueryStringW,
        IShellItemImageFactory, SHCreateItemFromParsingName, SHFILEINFOW, SHGFI_SYSICONINDEX,
        SHGFI_TYPENAME, SHGFI_USEFILEATTRIBUTES, SHGetFileInfoW, SHGetImageList, SHIL_EXTRALARGE,
        SHIL_SMALL, SIIGBF_BIGGERSIZEOK, SIIGBF_THUMBNAILONLY,
    };
    use windows::Win32::UI::WindowsAndMessaging::{DestroyIcon, GetIconInfo, HICON, ICONINFO};
    use windows::core::{HSTRING, PCWSTR, PWSTR};

    use super::{Bitmap, FileIcon};
    use crate::files::{Entry, EntryKind};

    static TYPE_NAMES: LazyLock<Mutex<HashMap<String, Option<String>>>> =
        LazyLock::new(Default::default);

    thread_local! {
        // Type names are looked up on background pool threads.
        static COM: () = unsafe {
            let _ = CoInitializeEx(None, COINIT_MULTITHREADED);
        };
    }

    pub fn init_thread() {
        // SAFETY: Called once at the start of the worker thread.
        let _ = unsafe { CoInitializeEx(None, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE) };
    }

    pub fn type_name(entry: &Entry) -> Option<String> {
        let key = match entry.kind {
            EntryKind::Directory => String::new(),
            EntryKind::Archive | EntryKind::File => format!(".{}", entry.extension()?),
            EntryKind::Unavailable => return None,
        };
        let mut cache = TYPE_NAMES.lock().unwrap_or_else(|err| err.into_inner());
        cache
            .entry(key)
            .or_insert_with_key(|key| {
                COM.with(|_| ());
                if key.is_empty() {
                    folder_type_name()
                } else {
                    friendly_type_name(key)
                }
            })
            .clone()
    }

    /// `None` for extensions that no application has registered. Windows
    /// would otherwise make up a name such as "XYZ File".
    fn friendly_type_name(extension: &str) -> Option<String> {
        let extension = HSTRING::from(extension);
        let mut key = HKEY::default();
        // SAFETY: `key` is closed right after the check.
        unsafe {
            RegOpenKeyExW(HKEY_CLASSES_ROOT, &extension, None, KEY_READ, &mut key)
                .ok()
                .ok()?;
            let _ = RegCloseKey(key);
        }
        let mut buffer = [0u16; 256];
        let mut len = buffer.len() as u32;
        // SAFETY: `buffer` holds `len` characters.
        unsafe {
            AssocQueryStringW(
                ASSOCF_INIT_IGNOREUNKNOWN,
                ASSOCSTR_FRIENDLYDOCNAME,
                &extension,
                PCWSTR::null(),
                Some(PWSTR(buffer.as_mut_ptr())),
                &mut len,
            )
            .ok()
            .ok()?;
        }
        let name = String::from_utf16_lossy(&buffer[..len.saturating_sub(1) as usize]);
        (!name.is_empty()).then_some(name)
    }

    fn folder_type_name() -> Option<String> {
        let mut info = SHFILEINFOW::default();
        // SAFETY: `info` is a valid SHFILEINFOW of the size passed.
        let found = unsafe {
            SHGetFileInfoW(
                &HSTRING::from("folder"),
                FILE_ATTRIBUTE_DIRECTORY,
                Some(&mut info),
                size_of::<SHFILEINFOW>() as u32,
                SHGFI_TYPENAME | SHGFI_USEFILEATTRIBUTES,
            )
        };
        if found == 0 {
            return None;
        }
        let len = info.szTypeName.iter().position(|&c| c == 0).unwrap_or(0);
        (len > 0).then(|| String::from_utf16_lossy(&info.szTypeName[..len]))
    }

    pub fn file_icon(extension: &str) -> Option<FileIcon> {
        let dotted = format!(".{extension}");
        friendly_type_name(&dotted)?;
        let mut info = SHFILEINFOW::default();
        // SAFETY: `info` is a valid SHFILEINFOW of the size passed.
        let found = unsafe {
            SHGetFileInfoW(
                &HSTRING::from(format!("file{dotted}")),
                FILE_ATTRIBUTE_NORMAL,
                Some(&mut info),
                size_of::<SHFILEINFOW>() as u32,
                SHGFI_SYSICONINDEX | SHGFI_USEFILEATTRIBUTES,
            )
        };
        if found == 0 {
            return None;
        }
        Some(FileIcon {
            small: system_icon(SHIL_SMALL, info.iIcon)?,
            large: system_icon(SHIL_EXTRALARGE, info.iIcon)?,
        })
    }

    fn system_icon(size: u32, index: i32) -> Option<Bitmap> {
        // SAFETY: The icon is destroyed after it has been copied.
        unsafe {
            let list: IImageList = SHGetImageList(size as i32).ok()?;
            let icon = list.GetIcon(index, ILD_TRANSPARENT.0).ok()?;
            let bitmap = icon_bitmap(icon);
            let _ = DestroyIcon(icon);
            bitmap
        }
    }

    unsafe fn icon_bitmap(icon: HICON) -> Option<Bitmap> {
        let mut info = ICONINFO::default();
        // SAFETY: `icon` is a valid icon; both bitmaps are deleted below.
        unsafe {
            GetIconInfo(icon, &mut info).ok()?;
            let mut color = read_bitmap(info.hbmColor);
            // Icons without an alpha channel mark transparency in the mask.
            if let Some(color) = &mut color
                && color.pixels.as_chunks::<4>().0.iter().all(|px| px[3] == 0)
                && let Some(mask) = read_bitmap(info.hbmMask)
            {
                for (px, mask) in color
                    .pixels
                    .as_chunks_mut::<4>()
                    .0
                    .iter_mut()
                    .zip(mask.pixels.as_chunks::<4>().0.iter())
                {
                    px[3] = 255 - mask[0];
                }
            }
            let _ = DeleteObject(info.hbmColor.into());
            let _ = DeleteObject(info.hbmMask.into());
            color
        }
    }

    pub fn thumbnail(path: &Path, size: u32) -> Option<Bitmap> {
        let size = i32::try_from(size).ok()?;
        // SAFETY: The bitmap is deleted after it has been copied.
        let mut bitmap = unsafe {
            let factory: IShellItemImageFactory =
                SHCreateItemFromParsingName(&HSTRING::from(path.as_os_str()), None).ok()?;
            let handle = factory
                .GetImage(
                    SIZE { cx: size, cy: size },
                    SIIGBF_THUMBNAILONLY | SIIGBF_BIGGERSIZEOK,
                )
                .ok()?;
            let bitmap = read_bitmap(handle);
            let _ = DeleteObject(handle.into());
            bitmap?
        };
        // Thumbnails are premultiplied, or have no alpha at all.
        if bitmap.pixels.as_chunks::<4>().0.iter().all(|px| px[3] == 0) {
            bitmap
                .pixels
                .as_chunks_mut::<4>()
                .0
                .iter_mut()
                .for_each(|px| px[3] = 255);
        } else {
            for px in bitmap.pixels.as_chunks_mut::<4>().0.iter_mut() {
                let alpha = u32::from(px[3]);
                if alpha > 0 && alpha < 255 {
                    for channel in &mut px[..3] {
                        *channel = (u32::from(*channel) * 255 / alpha).min(255) as u8;
                    }
                }
            }
        }
        Some(bitmap)
    }

    /// Copies a bitmap into top-down 32-bit BGRA.
    unsafe fn read_bitmap(handle: HBITMAP) -> Option<Bitmap> {
        let mut header = BITMAP::default();
        // SAFETY: `header` is a valid BITMAP of the size passed, and `pixels`
        // holds `width * height` 32-bit pixels.
        unsafe {
            let read = GetObjectW(
                handle.into(),
                size_of::<BITMAP>() as i32,
                Some((&mut header as *mut BITMAP).cast::<c_void>()),
            );
            if read == 0 || header.bmWidth <= 0 || header.bmHeight == 0 {
                return None;
            }
            let (width, height) = (header.bmWidth, header.bmHeight.abs());
            let mut info = BITMAPINFO {
                bmiHeader: BITMAPINFOHEADER {
                    biSize: size_of::<BITMAPINFOHEADER>() as u32,
                    biWidth: width,
                    biHeight: -height,
                    biPlanes: 1,
                    biBitCount: 32,
                    biCompression: BI_RGB.0,
                    ..Default::default()
                },
                ..Default::default()
            };
            let mut pixels = vec![0u8; width as usize * height as usize * 4];
            let dc = CreateCompatibleDC(None);
            let lines = GetDIBits(
                dc,
                handle,
                0,
                height as u32,
                Some(pixels.as_mut_ptr().cast()),
                &mut info,
                DIB_RGB_COLORS,
            );
            let _ = DeleteDC(dc);
            (lines == height).then_some(Bitmap {
                width: width as u32,
                height: height as u32,
                pixels,
            })
        }
    }
}

#[cfg(not(windows))]
mod imp {
    use std::path::Path;

    use super::{Bitmap, FileIcon};
    use crate::files::Entry;

    pub fn init_thread() {}

    pub fn type_name(_: &Entry) -> Option<String> {
        None
    }

    pub fn file_icon(_: &str) -> Option<FileIcon> {
        None
    }

    pub fn thumbnail(_: &Path, _: u32) -> Option<Bitmap> {
        None
    }
}

#[cfg(all(test, windows))]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use crate::files::EntryKind;

    fn file(name: &str) -> Entry {
        Entry::new(
            name.into(),
            PathBuf::from(name),
            EntryKind::File,
            Some(1),
            None,
        )
    }

    #[test]
    fn names_and_icons_only_registered_types() {
        imp::init_thread();
        assert!(type_name(&file("notes.txt")).is_some());
        assert_eq!(type_name(&file("model.lfunregistered")), None);

        let icon = imp::file_icon("txt").expect("text files have an icon");
        assert!(icon.large.width > icon.small.width);
        assert_eq!(
            icon.large.pixels.len(),
            (icon.large.width * icon.large.height * 4) as usize
        );
        assert!(imp::file_icon("lfunregistered").is_none());
    }
}
