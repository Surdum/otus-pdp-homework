# Nginx log parser

## Using

### Set config.ini file

Example:

```ini
[Config]
REPORT_SIZE=1000
REPORT_DIR=.\reports
LOG_DIR=.\log
FAIL_THRESHOLD=0.9
LOG_FILE=console.log
```

### Run log_analyzer.py file
```bash
python3 .\log_analyzer.py [--config config.ini]
```
