import argparse
import asyncio
from collections import deque

import uvloop
asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())

import sys
import math
import base64
import os
import traceback
import hashlib
import aiohttp
import aioprocessing
import logging
import locale

try:
    locale.setlocale(locale.LC_ALL, 'en_US')
except:
    pass

from OpenSSL import crypto

from . import certlib

DOWNLOAD_CONCURRENCY = 50
MAX_QUEUE_SIZE = 1000

async def download_worker(session, log_info, work_deque, download_queue):
    while True:
        try:
            start, end = work_deque.popleft()
        except IndexError:
            return

        logging.debug("[{}] Queueing up blocks {}-{}...".format(log_info['url'], start, end))

        for x in range(3):
            try:
                async with session.get(certlib.DOWNLOAD.format(log_info['url'], start, end)) as response:
                    entry_list = await response.json()
                    logging.debug("[{}] Retrieved blocks {}-{}...".format(log_info['url'], start, end))
                    break
            except Exception as e:
                logging.error("Exception getting block {}-{}! {}".format(start, end, e))
        else:  # Notorious for else, if we didn't encounter a break our request failed 3 times D:
            with open('/tmp/fails.csv', 'a') as f:
                f.write(",".join([log_info['url'], str(start), str(end)]))
            return

        for index, entry in zip(range(start, end + 1), entry_list['entries']):
            entry['cert_index'] = index

        await download_queue.put({
            "entries": entry_list['entries'],
            "log_info": log_info,
            "start": start,
            "end": end
        })

async def queue_monitor(log_info, work_deque, download_results_queue):
    total_size = log_info['tree_size'] - 1
    total_blocks = math.ceil(total_size / log_info['block_size'])

    while True:
        logging.info("Queue Status: Processing Queue Size:{3} Downloaded blocks:{0}/{1} ({2:.4f}%)".format(
            total_blocks - len(work_deque),
            total_blocks,
            ((total_blocks - len(work_deque)) / total_blocks) * 100,
            len(download_results_queue._queue),
        ))
        await asyncio.sleep(2)

async def retrieve_certificates(loop, url=None, ctl_offset=0, output_directory='/tmp/', concurrency_count=DOWNLOAD_CONCURRENCY):
    async with aiohttp.ClientSession(loop=loop, conn_timeout=10) as session:
        ctl_logs = await certlib.retrieve_all_ctls(session)

        if url:
            url = url.strip("'")

        for log in ctl_logs:
            if url and url not in log['url']:
                continue
            work_deque = deque()
            download_results_queue = asyncio.Queue(maxsize=MAX_QUEUE_SIZE)

            logging.info("Downloading certificates for {}".format(log['description']))
            try:
                log_info = await certlib.retrieve_log_info(log, session)
            except (aiohttp.ClientConnectorError, aiohttp.ServerTimeoutError, aiohttp.ClientOSError, aiohttp.ClientResponseError) as e:
                logging.error("Failed to connect to CTL! -> {} - skipping.".format(e))
                continue

            try:
                await certlib.populate_work(work_deque, log_info, start=ctl_offset)
            except Exception as e:
                logging.error("Log needs no update - {}".format(e))
                continue

            download_tasks = asyncio.gather(*[
                download_worker(session, log_info, work_deque, download_results_queue)
                for _ in range(concurrency_count)
            ])

            processing_task    = asyncio.ensure_future(processing_coro(download_results_queue, output_dir=output_directory))
            queue_monitor_task = asyncio.ensure_future(queue_monitor(log_info, work_deque, download_results_queue))

            asyncio.ensure_future(download_tasks)

            await download_tasks

            await download_results_queue.put(None) # Downloads are done, processing can stop

            await processing_task

            queue_monitor_task.cancel()

            logging.info("Completed {}, stored at {}!".format(
                log_info['description'],
                '/tmp/{}.csv'.format(log_info['url'].replace('/', '_'))
            ))

            logging.info("Finished downloading and processing {}".format(log_info['url']))

async def processing_coro(download_results_queue, output_dir="/tmp"):
    logging.info("Starting processing coro and process pool")
    process_pool = aioprocessing.AioPool(initargs=(output_dir,))

    done = False

    while True:
        entries_iter = []
        logging.info("Getting things to process...")
        for _ in range(int(process_pool.pool_workers)):
            entries = await download_results_queue.get()
            if entries != None:
                entries_iter.append(entries)
            else:
                done = True
                break

        logging.debug("Got a chunk of {}. Mapping into process pool".format(process_pool.pool_workers))


        for entry in entries_iter:
            csv_storage = '{}/certificates/{}'.format(output_dir, entry['log_info']['url'].replace('/', '_'))
            if not os.path.exists(csv_storage):
                print("[{}] Making dir...".format(os.getpid()))
                os.makedirs(csv_storage)
            entry['log_dir']=csv_storage

        if len(entries_iter) > 0:
            await process_pool.coro_map(process_worker, entries_iter)

        logging.debug("Done mapping! Got results")

        if done:
            break

    process_pool.close()

    await process_pool.coro_join()

def process_worker(result_info):
    logging.debug("Worker {} starting...".format(os.getpid()))
    if not result_info:
        return
    try:
        csv_storage = result_info['log_dir']
        csv_file = "{}/{}-{}.csv".format(csv_storage, result_info['start'], result_info['end'])

        lines = []

        print("[{}] Parsing...".format(os.getpid()))
        for entry in result_info['entries']:
            mtl = certlib.MerkleTreeHeader.parse(base64.b64decode(entry['leaf_input']))

            cert_data = {}

            if mtl.LogEntryType == "X509LogEntryType":
                cert_data['type'] = "X509LogEntry"
                chain = [crypto.load_certificate(crypto.FILETYPE_ASN1, certlib.Certificate.parse(mtl.Entry).CertData)]
                extra_data = certlib.CertificateChain.parse(base64.b64decode(entry['extra_data']))
                for cert in extra_data.Chain:
                    chain.append(crypto.load_certificate(crypto.FILETYPE_ASN1, cert.CertData))
            else:
                cert_data['type'] = "PreCertEntry"
                extra_data = certlib.PreCertEntry.parse(base64.b64decode(entry['extra_data']))
                chain = [crypto.load_certificate(crypto.FILETYPE_ASN1, extra_data.LeafCert.CertData)]

                for cert in extra_data.Chain:
                    chain.append(
                        crypto.load_certificate(crypto.FILETYPE_ASN1, cert.CertData)
                    )

            cert_data.update({
                "leaf_cert": certlib.dump_cert(chain[0]),
                "chain": [certlib.dump_cert(x) for x in chain[1:]]
            })

            certlib.add_all_domains(cert_data)

            cert_data['source'] = {
                "url": result_info['log_info']['url'],
            }

            chain_hash = hashlib.sha256("".join([x['as_der'] for x in cert_data['chain']]).encode('ascii')).hexdigest()

            # header = "url, cert_index, chain_hash, cert_der, all_domains, not_before, not_after"
            lines.append(
                ",".join([
                    result_info['log_info']['url'],
                    str(entry['cert_index']),
                    chain_hash,
                    cert_data['leaf_cert']['as_der'],
                    ' '.join(cert_data['leaf_cert']['all_domains']),
                    str(cert_data['leaf_cert']['not_before']),
                    str(cert_data['leaf_cert']['not_after'])
                ]) + "\n"
            )

        print("[{}] Finished, writing CSV...".format(os.getpid()))

        with open(csv_file, 'w', encoding='utf8') as f:
            f.write("".join(lines))
        print("[{}] CSV {} written!".format(os.getpid(), csv_file))

    except Exception as e:
        print("========= EXCEPTION =========")
        traceback.print_exc()
        print(e)
        print("=============================")

    return True

async def get_certs_and_print():
    async with aiohttp.ClientSession(conn_timeout=5) as session:
        ctls = await certlib.retrieve_all_ctls(session)
        print("Found {} CTLs...".format(len(ctls)))
        for log in ctls:
            try:
                log_info = await certlib.retrieve_log_info(log, session)
            except:
                continue

            print(log['description'])
            print("    \- URL:            {}".format(log['url']))
            print("    \- Owner:          {}".format(log_info['operated_by']))
            print("    \- Cert Count:     {}".format(locale.format("%d", log_info['tree_size']-1, grouping=True)))
            print("    \- Max Block Size: {}\n".format(log_info['block_size']))

def main():
    loop = asyncio.get_event_loop()

    parser = argparse.ArgumentParser(description='Pull down certificate transparency list information')

    parser.add_argument('-f', dest='log_file', action='store', default='/tmp/axeman.log',
                        help='location for the axeman log file')

    parser.add_argument('-s', dest='start_offset', action='store', default=0,
                        help='Skip N number of lists before starting')

    parser.add_argument('-l', dest="list_mode", action="store_true", help="List all available certificate lists")

    parser.add_argument('-u', dest="ctl_url", action="store", default=None, help="Retrieve this CTL only")

    parser.add_argument('-z', dest="ctl_offset", action="store", default=0, help="The CTL offset to start at")

    parser.add_argument('-o', dest="output_dir", action="store", default="/tmp", help="The output directory to store certificates in")

    parser.add_argument('-v', dest="verbose", action="store_true", help="Print out verbose/debug info")

    parser.add_argument('-c', dest='concurrency_count', action='store', default=50, type=int, help="The number of concurrent downloads to run at a time")

    args = parser.parse_args()

    if args.list_mode:
        loop.run_until_complete(get_certs_and_print())
        return

    handlers = [logging.FileHandler(args.log_file), logging.StreamHandler()]

    if args.verbose:
        logging.basicConfig(format='[%(levelname)s:%(name)s] %(asctime)s - %(message)s', level=logging.DEBUG, handlers=handlers)
    else:
        logging.basicConfig(format='[%(levelname)s:%(name)s] %(asctime)s - %(message)s', level=logging.INFO, handlers=handlers)

    logging.info("Starting...")

    if args.ctl_url:
        loop.run_until_complete(retrieve_certificates(loop, url=args.ctl_url, ctl_offset=int(args.ctl_offset), concurrency_count=args.concurrency_count, output_directory=args.output_dir))
    else:
        loop.run_until_complete(retrieve_certificates(loop, concurrency_count=args.concurrency_count, output_directory=args.output_dir))

if __name__ == "__main__":
    main()
