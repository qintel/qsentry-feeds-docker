import os
from qintel_helper import qsentry_feed
from datetime import datetime
import shutil
from io import StringIO
import csv
import logging
import types
import json

logger = logging.getLogger(__name__)

remote = os.getenv('QSENTRY_REMOTE', 'https://qsentry.qintel.com')
token = os.getenv('QSENTRY_TOKEN', '')
feed_type = os.getenv('QSENTRY_FEED', 'anon')
format_type = os.getenv('QSENTRY_FORMAT', 'zeek')


feed_mapping = {
    'anon': 'anonymization',
    'mal_hosting': 'malicious_hosting'
}

SUPPORTED_FEEDS = ['anonymization', 'malicious_hosting']

itype = {
    'ip_address': 'ADDR',
    'cidr': 'SUBNET',
    'url': 'URL',
    'fqdn': 'DOMAIN'
}
ANON_COLUMNS = [
    'fields',
    'indicator',
    'indicator_type',
    'meta.qsentry_comment',
    'meta.qsentry_service_name',
    'meta.qsentry_service_type',
    'meta.qsentry_criminal',
    'meta.qsentry_cdn',
    'meta.source',
    'meta.do_notice'
]
MAL_COLUMNS = [
    'fields',
    'indicator',
    'indicator_type',
    'meta.qsentry_asn',
    'meta.qsentry_comment',
    'meta.source',
    'meta.do_notice'
]
QSENTRY_ANON_FIELDS = [
    'ip_address',
    'itype',
    'comment',
    'service_name',
    'service_type',
    'criminal',
    'cdn'
]
QSENTRY_MAL_FIELDS = [
    'cidr',
    'itype',
    'asn',
    'comment'
]
SEP = '|'


def _i_to_zeek(i, fields, feed_type):
    r = []
    if feed_type == 'anon':
        i['itype'] = 'ip_address'
    if feed_type == 'mal_hosting':
        i['itype'] = 'cidr'

    for c in fields:
        if c == 'itype':
            i['itype'] = f'Intel::{itype[i[c]]}'

        y = i.get(c, '-')

        r.append(str(y))
    r += ['Qintel QSentry', 'T']
    return "\t".join(r)


def pull_feed(feed_type):
    qsentry_args = {'remote': remote, 'token': token}
    return qsentry_feed(feed_type, **qsentry_args)


def generate_zeek(data):
    if feed_type == 'anon':
        fields = QSENTRY_ANON_FIELDS
        header = '#' + '\t'.join(ANON_COLUMNS)
    if feed_type == 'mal_hosting':
        fields = QSENTRY_MAL_FIELDS
        header = '#' + '\t'.join(MAL_COLUMNS)

    output = []
    for i in data:
        i = _i_to_zeek(i, fields, feed_type)
        output.append(i)

    output = "\n".join(output)
    output = f"{header}\n{output}"

    return output


def generate_checkpoint(data):
    # This only supports anonymization
    csvfile = StringIO()

    # Set header values prepended with pound symbol
    keys = ["#Value", "Type", "Confidence", "Severity", "Comment"]
    # set up csv.writer object
    q = csv.writer(csvfile, quotechar='"', quoting=csv.QUOTE_NONNUMERIC)
    # Write header row to file
    q.writerow(keys)

    # iterate though dataset and add hardcoded defaults for certain values
    for each in data:
        itype = 'ip'
        confidence = 'high'
        severity = 'medium'
        if each.get('criminal', 0) == 1:
            severity = 'high'
        q.writerow([each.get('ip_address'), itype, confidence, severity, each.get('comment')])

    output = csvfile.getvalue().splitlines()
    csvfile.close()
    return output


def main():
    if format_type == 'zeek' and feed_mapping[feed_type] not in SUPPORTED_FEEDS:
        logger.error('{} not a supported feed for {} output'.format(feed_type, __name__))
        return
    if format_type == 'checkpoint' and feed_type != 'anon':
        logger.error('{} not a supported feed for {} output'.format(feed_type, __name__))
        return

    currenttime = datetime.now().strftime("%Y-%m-%dT%H:%M:%S")
    timestampfile = f"/feeds/qsentry-{feed_mapping[feed_type]}-{format_type}-{currenttime}.out"
    currentfile = f"/feeds/qsentry-{feed_mapping[feed_type]}-{format_type}-current.out"

    feed_data = pull_feed(feed_type)
    output = ''

    if format_type == 'zeek':
        output = generate_zeek(feed_data)

    if format_type == 'checkpoint':
        output = generate_checkpoint(feed_data)

    with open(timestampfile, 'w') as f:
        if isinstance(output, str):
            f.write(output)
        elif isinstance(output, list) or isinstance(output,
                                                    types.GeneratorType):
            f.writelines('{}\n'.format(l) for l in output)
        elif isinstance(output, dict):
            json.dump(output, f, indent=4)
        else:
            logger.error(
                f'Returned an unexpected output type of {type(output)}.')

    shutil.copyfile(timestampfile, currentfile)


if __name__ == '__main__':
    main()
