#!/usr/bin/env python3
import os
import os.path
import signal
import sys
import time
import logging

path = "/voicemail"
maxfileage = 3600  # 1h
maxfilesize = 1073741824  # 1gb
maxdirsize = 5368709120  # 5gb
maxfilecount = 100  # per directory
sleep = 1  # 1 second
dirnames = ["INBOX", "tmp"]


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


def main():
    while 1:
        marked4deletion = list()
        for dirname in dirnames:
            dirsize = 0
            dirname = os.path.join(path, dirname)
            if not os.path.exists(dirname):
                logging.info("creating directory %s" % dirname)
                os.makedirs(dirname, exist_ok=True)
                continue
            try:
                shortfns = os.listdir(dirname)
            except FileNotFoundError:
                continue
            except OSError as exc:
                logging.warning("skipping directory %s: %s", dirname, exc)
                continue
            filenames = list()
            for shortfn in shortfns:
                filenames.append(os.path.join(dirname, shortfn))
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
        time.sleep(sleep)


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
