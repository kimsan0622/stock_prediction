import os
import argparse

from selenium import webdriver
import selenium
from bs4 import BeautifulSoup
import html5lib
import requests
import tqdm

parser = argparse.ArgumentParser()
parser.add_argument("--chrome_driver_path", default='/home/san/backup/workspace/crawler/web_driver/chromedriver', type=str, help="path to chrome driver. you can download it from https://chromedriver.chromium.org/getting-started. of course, you should install Chrome web browser in your machine.")
parser.add_argument("--iex_web_url", default='https://iextrading.com/trading/market-data/', type=str, help="web url of iex market data page")
parser.add_argument("--base_dir", default='./raw_data', type=str, help="path to directory for raw data.")
parser.add_argument('--target', default='both', type=str, choices=['deep', 'tops', 'both'], help='you can choose a download target in [both, tops, deep]. if you want to download the DEEP data set, choose it! if you want to download both TOPS and DEEP, please choose \'both\'. default value of this parameter is \'both\'')
args = parser.parse_args()

def download(url, file_name):
    with open(file_name, "wb") as file:   
        response = requests.get(url)               
        file.write(response.content)

def check_directory(dir_name):
    if not os.path.isdir(dir_name):
        os.makedirs(dir_name)

if __name__ == "__main__":

    driver = webdriver.Chrome(args.chrome_driver_path)

    driver.get(args.iex_web_url)

    contents = driver.page_source
    contents = contents.replace("<!--","")
    contents = contents.replace("-->","")
    soup = BeautifulSoup(contents, 'html5lib')

    records = soup.select('#hist-rows > tr')

    tops_list = dict()
    deep_list = dict()

    for record in records:
        data = dict()
        tds = record.find_all('td')
        data['date'] = tds[0].get_text()
        data['type'] = tds[1].a.get_text()
        data['url'] = tds[1].a['href']
        data['ver'] = tds[2].get_text()
        data['pkt_ver'] = tds[3].get_text()
        data['key'] = '{0}_{1}.pcap.gz'.format(data['date'], data['type'])
        data['file_name'] = '{0}_{1}_{2}.pcap.gz'.format(data['date'], data['type'], data['ver'])

        if data['type'] == 'TOPS':
            if data['key'] not in tops_list.keys():
                tops_list[data['key']] = data
            elif float(data['ver'][1:]) > float(tops_list[data['key']]['ver'][1:]):
                tops_list[data['key']] = data

        elif data['type'] == 'DEEP':
            if data['key'] not in deep_list.keys():
                deep_list[data['key']] = data
            elif float(data['ver'][1:]) > float(deep_list[data['key']]['ver'][1:]):
                deep_list[data['key']] = data

    driver.quit()

    tops_dir = os.path.join(args.base_dir, 'tops')
    deep_dir = os.path.join(args.base_dir, 'deep')
    is_tops_download = args.target == 'both' or args.target == 'tops'
    is_deep_download = args.target == 'both' or args.target == 'deep'

    if is_tops_download:
        print('download TOPS')
        check_directory(tops_dir)
        for key, data in tqdm.tqdm(tops_list.items(), desc='files: '):
            download(data['url'], os.path.join(tops_dir, data['file_name']))

    if is_deep_download:
        print('download DEEP')
        check_directory(deep_dir)
        for key, data in tqdm.tqdm(deep_list.items(), desc='files: '):
            download(data['url'], os.path.join(deep_dir, data['file_name']))

    print('download finished')