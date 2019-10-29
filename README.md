# stock_prediction
stock price prediction using deep learning algorithms. The models will be trained using Kiwoom api+ and IEX data set.

## data preprocessing
### IEX dataset
This project provides modules for parsing IEX data from scratch. In this project, we use MongoDB for querying data, about the IEX dataset.
Please refer the [**IEX Preprocessing**](./iex/parsing/README.md) if you want parsing data from scratch. But I recommend that you use the data which was processed because it takes too much time.
You can find the way How to get data that you want in [**IEX data**](./iex/README.md).