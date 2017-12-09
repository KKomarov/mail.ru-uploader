# mail.ru-cli
Unofficial mail.ru cloud file command line tools. Check official license agreement first (https://cloud.mail.ru/LA/).

### Prerequisities

Python 3.3+ (2.7+ might be enough as well)

### Installing

```
pip3 install .
```

### Using
Similar to unix
```
cmr ls
cmr cp cmr://1.txt .
cmr cp -r tests/ cmr://myproj/tests
```

### To do
- download from cloud recursive option
- rm command
- mv command

## Running the tests
Install pytest in your virtual environment if not installed:
```
pip install pytest
```

To run tests from shell use:
```
py.test
```

Provide email credentials if configuration file is not ok:
```
py.test --email=your_email@mail.ru --password=your_password
```

Pass --runweb option to run cloud related tests
```
py.test --runweb
```

Pass --rundirty option to run cloud related tests which will leave some data in the cloud's recycle bin
```
py.test --rundirty
```

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details
