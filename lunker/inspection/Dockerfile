### browsertrix-crawler v1.2.4 ###

FROM webrecorder/browsertrix-crawler:latest

ENTRYPOINT crawl --url ${INSPECT_URL} --generateWACZ --text to-warc,final-to-warc --screenshot thumbnail,view,fullPage
