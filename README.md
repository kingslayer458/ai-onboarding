Run backend, open frontend/index.html, download and run agent.exe after building it.

pip install pyinstaller
 python -m PyInstaller --onefile --clean agent.py
 remove typing if you got any error

 then transfer the exe into /backend folder

 to run the server

 cd backend

 node server.js

python -m pyinstaller --clean --onefile --hidden-import=psutil --hidden-import=websocket --hidden-import=compatibility agent.py

python -m PyInstaller \
  --clean \
  --onefile \
  --hidden-import=psutil \
  --hidden-import=websocket \
  --hidden-import=compatibility \
  agent.py

  python -m PyInstaller --clean --onefile --collect-all psutil --hidden-import=compatibility  --hidden-import=websocket  agent.py
python -m pip install websocket-client