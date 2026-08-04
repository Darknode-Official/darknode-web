Put the built desktop-app installers here so the website can serve them directly.
The landing page's download buttons link to these exact filenames:

  Sentinel-linux.AppImage     (Linux)   built with:  npm run dist:linux   (in sentinel-app)
  Sentinel-windows.exe        (Windows) built with:  npm run dist:win     (on Windows)
  Sentinel-mac.dmg            (macOS)   built with:  npm run dist:mac     (on macOS)

How to fill this folder:
  1. In ~/projects/sentinel-app, build the installer for a given OS (see its README).
     electron-builder writes the file to sentinel-app/dist/ (e.g. Sentinel-1.0.0.AppImage).
  2. Rename it to the matching name above and copy it into this folder
     (~/projects/sentinel-web/public/downloads/).
  3. Re-upload the public/ folder to Netlify. The button now downloads it from the site.

Notes:
  - You can only build the Windows/Mac installers on those operating systems (or via the
    GitHub Actions workflow in sentinel-app, which builds all three).
  - Installers are ~80-150 MB each; they count against Netlify bandwidth on every download.
  - This README is just a placeholder so the folder exists; you can delete it once the
    installers are in place.
