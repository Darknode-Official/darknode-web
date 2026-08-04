Put the built desktop-app installers here so the website can serve them directly.
The landing page's download buttons link to these exact filenames:

  Sentinel-linux.deb        (Linux)   built with:  npm run dist:linux   (in sentinel-app)
  Sentinel-linux.AppImage   (Linux)   built with:  npm run dist:linux   (portable, non-Debian distros)
  Sentinel-windows.exe      (Windows) built with:  npm run dist:win     (on Windows or via Wine)

How to fill this folder:
  1. In ~/projects/sentinel-app, build the installer:
       npm run dist:linux    -> dist/sentinel-app_1.0.0_amd64.deb   (also builds an AppImage)
       npm run dist:win       -> dist/Sentinel Setup 1.0.0.exe
  2. Copy + rename into this folder:
       cp dist/sentinel-app_1.0.0_amd64.deb  Sentinel-linux.deb
       cp "dist/Sentinel Setup 1.0.0.exe"    Sentinel-windows.exe
  3. Re-upload the public/ folder to Netlify (drag-drop, or: netlify deploy --prod --dir=public).

What users run after downloading:
  Linux    sudo apt install ./Sentinel-linux.deb      (then launch "Sentinel" from the app menu, or run: sentinel)
  Windows  double-click Sentinel-windows.exe          (SmartScreen: More info -> Run anyway; installer is unsigned)

Notes:
  - The .deb is preferred over the AppImage on Linux: no FUSE dependency, it sets up the
    Chromium sandbox correctly, and it adds Sentinel to the application menu automatically.
  - Installers are ~90-100 MB each; they count against Netlify bandwidth on every download.
  - Installers are git-ignored, so deploy by uploading the public/ folder, not via a git build.
