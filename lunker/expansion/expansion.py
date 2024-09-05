import boto3
import os
from warcio.archiveiterator import ArchiveIterator
from zipfile import ZipFile

s3 = boto3.client('s3')

s3.download_file(
    os.environ['S3_DOWNLOAD'],
    os.environ['CRAWL_ID']+'/'+os.environ['CRAWL_ID']+'.wacz',
    '/tmp/'+os.environ['CRAWL_ID']+'.wacz'
)

with ZipFile('/tmp/'+os.environ['CRAWL_ID']+'.wacz', 'r') as zip:

	for file in zip.namelist():
		if file.startswith("archive") and file.endswith(".warc.gz"):
			print('*** '+file+' ***')
			with zip.open(file) as stream:
				for record in ArchiveIterator(stream):
					if record.rec_type == 'response':
						url = record.rec_headers.get_header("WARC-Target-URI")
						url = url.split('://')[1]
						url = url.replace('/','_')
						if '?' in url:
							url = url.split('?')[0]
						if len(url) > 254:
							url = url[:235]+'TRUNCATED'+url[-10:]

						with open('/tmp/'+url, 'wb') as data:
							data.write(record.content_stream().read())

						s3.upload_file(
							'/tmp/'+url,
							os.environ['S3_INSPECT'],
							os.environ['CRAWL_ID']+'/'+url
						)
