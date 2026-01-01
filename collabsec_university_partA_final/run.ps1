\
Set-Location $PSScriptRoot
python -m pip install -r .\requirements.txt
python -m streamlit run .\app\app.py
