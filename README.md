tradewave
=========

TradeWave Webapp: digital barter platform

### Dependencies
Install dependencies using:
`pip install`

### Celery background task processing system
Start celery from the top-level directory using:
`celery worker --app tradewave_beta  -l info`

### Redis server
Celery uses redis server as a broker. It needs to be installed and started using:
`redis-server`
