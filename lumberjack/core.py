import asyncio

import uvloop

asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())

import math
import base64
import sys
import os
import traceback
import hashlib
import aiohttp
import aioprocessing
import logging

from OpenSSL import crypto

from lumberjack import certlib

DOWNLOAD_CONCURRENCY = 50
MAX_QUEUE_SIZE = 1000

async def download_worker(session, log_info, work_queue, download_queue):
    while not work_queue.empty():
        start, end = await work_queue.get()
        logging.debug("Downloading {} {}-{}...".format(log_info['url'], start, end))

        for x in range(3):
            try:
                async with session.get(certlib.DOWNLOAD.format(log_info['url'], start, end)) as response:
                    entry_list = await response.json()
                    break
            except Exception as e:
                logging.error("Exception getting block {}-{}! {}".format(start, end, e))
        else:  # Notorious for else D:
            with open('/tmp/fails.csv', 'a') as f:
                f.write(",".join([log_info['url'], str(start), str(end)]))

            continue

        for index, entry in zip(range(start, end + 1), entry_list['entries']):
            entry['cert_index'] = index

        await download_queue.put({
            "entries": entry_list['entries'],
            "log_info": log_info,
            "start": start,
            "end": end
        })

    # Cleanup sentinal
    await download_queue.put(None)

async def queue_monitor(log_info, work_queue, download_results_queue):
    total_size = log_info['tree_size'] - 1
    total_blocks = math.ceil(total_size / log_info['block_size'])

    while True:
        logging.info("Queue Status: DOWNLOAD:{0}/{1} ({2:.4f}%) PROCESSING:{3}".format(
            total_blocks - len(work_queue._queue),
            total_blocks,
            ((total_blocks - len(work_queue._queue)) / total_blocks) * 100,
            len(download_results_queue._queue),
        ))
        await asyncio.sleep(2)

async def retrieve_certificates(loop, start=0):
    async with aiohttp.ClientSession(loop=loop, conn_timeout=10) as session:
        ctl_logs = await certlib.retrieve_all_ctls(session)

        for log in ctl_logs[start:]:
            work_queue = asyncio.Queue()
            download_results_queue = asyncio.Queue(maxsize=MAX_QUEUE_SIZE)

            logging.info("Downloading certificates for {}".format(log['description']))
            try:
                if log['url'].endswith('/'):
                    log['url'] = log['url'][:-1]
                log_info = await certlib.retrieve_log_info(log, session)
            except (aiohttp.ClientConnectorError, aiohttp.ServerTimeoutError, aiohttp.ClientOSError, aiohttp.ClientResponseError) as e:
                logging.error("Failed to connect to CTL! -> {} - skipping.".format(e))
                continue

            await certlib.populate_work_queue(work_queue, log_info)

            download_tasks = asyncio.gather(*[
                download_worker(session, log_info, work_queue, download_results_queue)
                for _ in range(DOWNLOAD_CONCURRENCY)
            ])

            processing_task    = asyncio.ensure_future(processing_coro(download_results_queue))
            queue_monitor_task = asyncio.ensure_future(queue_monitor(log_info, work_queue, download_results_queue))

            asyncio.ensure_future(download_tasks)

            await download_tasks
            await processing_task

            queue_monitor_task.cancel()

            logging.info("Completed {}, stored at {}!".format(
                log_info['description'],
                '/tmp/{}.csv'.format(log_info['url'].replace('/', '_'))
            ))

            logging.info("Finished downloading and processing {}".format(log_info['url']))

async def processing_coro(download_results_queue):
    logging.info("Starting processing coro and process pool")
    process_pool = aioprocessing.AioPool()

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

        logging.info("Got a chunk of {}. Mapping into process pool".format(process_pool.pool_workers))

        await process_pool.coro_map(process_worker, entries_iter)

        logging.info("Done mapping! Got results")

        if done:
            break

    process_pool.close()

    await process_pool.coro_join()

def process_worker(result_info):
    try:

        csv_storage = '/tmp/certificates/{}'.format(result_info['log_info']['url'].replace('/', '_'))

        csv_file = "{}/{}-{}.csv".format(csv_storage, result_info['start'], result_info['end'])

        lines = []

        if not os.path.exists(csv_storage):
            os.makedirs(csv_storage)

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

        with open(csv_file, 'w') as f:
            f.write("".join(lines))

    except Exception as e:
        print("========= EXCEPTION =========")
        traceback.print_exc()
        print(e)
        print("=============================")

    return True

def main():
    loop = asyncio.get_event_loop()

    handlers = [logging.FileHandler('/tmp/lumberjack.log'), logging.StreamHandler()]

    logging.basicConfig(format='[%(levelname)s:%(name)s] %(asctime)s - %(message)s', level=logging.DEBUG, handlers=handlers)

    logging.info("Starting...")

    start = 0

    if len(sys.argv) > 1:
        start = int(sys.argv[1])

    loop.run_until_complete(retrieve_certificates(loop, start))

if __name__ == "__main__":
    main()