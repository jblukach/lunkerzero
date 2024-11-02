### browsertrix-crawler v1.3.4 ###

FROM webrecorder/browsertrix-crawler:latest

ENTRYPOINT crawl --url ${INSPECT_URL} --generateWACZ --text to-warc,final-to-warc --workers 4
