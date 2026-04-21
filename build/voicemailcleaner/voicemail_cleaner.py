#!/usr/bin/env python3
import logging
import os
import os.path
import signal
import sys
import time

log_level_name = os.environ.get("CLEAN_LOG_LEVEL", "INFO").upper()
log_level = getattr(logging, log_level_name, logging.INFO)

logging.basicConfig(
    level=log_level,
    format="%(asctime)s %(levelname)s %(message)s",
)

path = os.environ.get("CLEAN_PATH", "/voicemail")
mode = os.environ.get("CLEAN_MODE", "flat-subdirs")
maxfileage = int(os.environ.get("MAX_FILE_AGE", "3600"))
maxfilesize = int(os.environ.get("MAX_FILE_SIZE", "1073741824"))
maxdirsize = int(os.environ.get("MAX_DIR_SIZE", "5368709120"))
maxfilecount = int(os.environ.get("MAX_FILE_COUNT", "100"))
sleep_interval = float(os.environ.get("CLEAN_SLEEP", "1"))
subdirs = [
    entry.strip()
    for entry in os.environ.get("CLEAN_SUBDIRS", "INBOX,tmp").split(",")
    if entry.strip()
]


def safe_stat(fullfn):
    try:
        return os.stat(fullfn)
    except FileNotFoundError:
        logging.info("file %s disappeared before it could be processed", fullfn)
    except OSError as exc:
        logging.warning("skipping %s: %s", fullfn, exc)
    return None


def safe_mtime(fullfn):
    filestat = safe_stat(fullfn)
    if filestat is None:
        return float("inf")
    return filestat.st_mtime


def iter_files_recursive(dirname):
    filenames = []
    for root, _, files in os.walk(dirname):
        for shortfn in files:
            filenames.append(os.path.join(root, shortfn))
    return filenames


def collect_filenames(dirname):
    if mode == "recursive":
        return iter_files_recursive(dirname)

    filenames = []
    for shortfn in os.listdir(dirname):
        filenames.append(os.path.join(dirname, shortfn))
    return filenames


def target_directories():
    if mode == "recursive":
        return [path]

    if not subdirs:
        return [path]

    return [os.path.join(path, dirname) for dirname in subdirs]


def main():
    logging.info(
        "storage cleaner starting: path=%s mode=%s max_age=%s max_file_size=%s max_dir_size=%s max_file_count=%s",
        path,
        mode,
        maxfileage,
        maxfilesize,
        maxdirsize,
        maxfilecount,
    )
    while 1:
        marked4deletion = list()
        for dirname in target_directories():
            dirsize = 0
            if not os.path.exists(dirname):
                logging.info("creating directory %s" % dirname)
                try:
                    os.makedirs(dirname, exist_ok=True)
                except OSError as exc:
                    logging.warning("cannot create directory %s yet: %s", dirname, exc)
                continue
            try:
                filenames = collect_filenames(dirname)
            except FileNotFoundError:
                continue
            except OSError as exc:
                logging.warning("skipping directory %s: %s", dirname, exc)
                continue
            if len(filenames) > maxfilecount:
                logging.info("directory %s exceeds max file count (%d > %d)" % (dirname, len(filenames), maxfilecount))
                filenames.sort(key=safe_mtime)
                marked4deletion.extend(filenames[:len(filenames) - maxfilecount])
            for fullfn in filenames:
                filestat = safe_stat(fullfn)
                if filestat is None:
                    continue
                mtime = filestat.st_mtime
                if time.time() - maxfileage >= mtime:
                    logging.info("file %s exceeds maximum age" % fullfn)
                    marked4deletion.append(fullfn)
                fsize = filestat.st_size
                if fsize >= maxfilesize:
                    logging.info("file %s exceeds maximum file size" % fullfn)
                    marked4deletion.append(fullfn)
                dirsize += fsize
                if dirsize >= maxdirsize:
                    logging.info("directory %s exceeds maximum directory size" % dirname)
                    marked4deletion.extend(filenames)
                    break
        marked4deletion = list(set(marked4deletion))
        for fn in marked4deletion:
            logging.info("removing %s" % fn)
            try:
                os.remove(fn)
            except FileNotFoundError:
                continue
            except OSError as exc:
                logging.warning("failed to remove %s: %s", fn, exc)
        time.sleep(sleep_interval)


def receiveSignal(signalNumber, frame):
    logging.info('Received signal %s, shutting down' % signalNumber)
    sys.exit(0)


signal.signal(signal.SIGTERM, receiveSignal)
signal.signal(signal.SIGINT, receiveSignal)

if __name__ == "__main__":
    try:
        main()
    except (KeyboardInterrupt, SystemExit):
        pass
