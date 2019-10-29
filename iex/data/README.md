# How to download IEX historical data

You can download the IEX historical data in [**here**](https://iextrading.com/trading/market-data/#hist-download).
But there are too many files. If you want to download files in one shot, use [**download_raw_files.py**](./download_raw_files.py).
You should install [**chrome web browser**](https://www.google.com/chrome) and download [**Chrome web driver**](https://chromedriver.chromium.org/getting-started).
After that, install [**requirements.txt**](../requirements.txt) if you didn't install it yet.

```bash
    pip install -r ../requirements.txt
```

description of [**download_raw_files.py**](./download_raw_files.py).

| `argument name` | `description` |
| --- | --- |
| **--chrome_driver_path** | path to directory that chrome driver is included. |
| **--iex_web_url** | web url of iex market data page. default value is [https://iextrading.com/trading/market-data/](https://iextrading.com/trading/market-data/). |
| **--base_dir** | path to directory for raw data. default value is './raw_data' |
| **--target** | you can choose a download target in [both, tops, deep]. if you want to download the DEEP data set, choose it! if you want to download both TOPS and DEEP, please choose 'both'. default value of this parameter is 'both' |

e.g.

```bash
    python download_raw_files.py --chrome_driver_path /home/user/Downloads/chromedriver \
        --iex_web_url 'https://iextrading.com/trading/market-data/' --base_dir ./iex_data --target 'both'
    # decompress the gz file using 'gzip' or 'gunzip'. (e.g. gzip -kvd *.gz) k: keep gz files, v: verbose, d: decompress in gzip
```
