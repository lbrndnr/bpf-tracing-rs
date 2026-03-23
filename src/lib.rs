use std::fs::File;
use std::io::Write;
use std::path::Path;
use std::sync::mpsc::{self, Receiver};
use std::time::Duration;
use tokio::{
    io::{AsyncReadExt, AsyncSeekExt, SeekFrom},
    time::sleep,
};

const TRACE_PIPE_PATH: &str = "/sys/kernel/debug/tracing/trace_pipe";

type Result<T> = std::result::Result<T, std::io::Error>;

pub fn try_init() -> Result<()> {
    Ok(())
}

fn observe<P: AsRef<Path>>(path: P) -> Result<Receiver<Result<String>>> {
    let path = path.as_ref().to_path_buf();
    let (tx, rx) = mpsc::channel::<Result<String>>();
    let file = File::open(&path)?;

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .thread_stack_size(8 * 1024 * 1024)
        .worker_threads(1)
        .max_blocking_threads(1)
        .build()?;

    rt.spawn(async move {
        let mut offset = 0u64;
        let mut file = tokio::fs::File::from_std(file);

        loop {
            let meta = match tokio::fs::metadata(&path).await {
                Ok(meta) => meta,
                Err(e) => {
                    tx.send(Err(e)).ok();
                    break;
                }
            };

            let len = meta.len();

            // File got truncated/rotated.
            if len < offset {
                offset = 0;
            }

            // If there's new data, read only the appended part.
            if len > offset {
                if let Err(e) = file.seek(SeekFrom::Start(offset)).await {
                    tx.send(Err(e)).ok();
                    break;
                }

                let mut buf = vec![0u8; (len - offset) as usize];
                if let Err(e) = file.read_exact(&mut buf).await {
                    tx.send(Err(e)).ok();
                    break;
                }
                offset = len;

                // Print appended bytes as text (lossy for non-UTF8).
                let text = String::from_utf8_lossy(&buf);
                tx.send(Ok(text.into_owned())).ok();
            }

            // Poll interval (tune as needed).
            sleep(Duration::from_millis(250)).await;
        }
    });

    Ok(rx)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn observe_nonexistent_file() {
        let temp_dir = tempfile::tempdir().unwrap();
        let path = temp_dir.path().join("test.log");

        assert!(observe(path).is_err());
    }

    #[test]
    fn observe_file_changes() {
        let temp_dir = tempfile::tempdir().unwrap();
        let path = temp_dir.path().join("test.log");
        let mut file = File::create(&path).unwrap();

        let mut rx = observe(path).unwrap();

        file.write_all(b"hello\n").unwrap();
        file.write_all(b"world\n").unwrap();

        assert_eq!(rx.recv().unwrap().unwrap(), "hello\n".to_string());
        assert_eq!(rx.recv().unwrap().unwrap(), "world\n".to_string());
    }
}
