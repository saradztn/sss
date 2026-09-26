# Demo Win — عينة Windows

هذه عينة **Python** تعمل على Windows بدون حاجة لـ gcc.

## التشغيل

```powershell
python samples\demo_app_win\demo_win.py --help
python samples\demo_app_win\demo_win.py --debug
python samples\demo_app_win\demo_win.py --connect
python samples\demo_app_win\demo_win.py -c samples\demo_app_win\config.ini -o %TEMP%\demo_output.txt
type %TEMP%\demo_output.txt
```

## للتحليل

```powershell
python -m revspec.cli analyze samples\demo_app_win\demo_win.py --output .\runs
python -m revspec.cli analyze samples\demo_app_win\demo_win.py --output .\runs --enable-dynamic --dynamic-args="--debug"
```
