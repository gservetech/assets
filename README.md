# gservetech assets

Public file storage for `https://assets.gservetech.com`.

Upload, replace, rename, and delete files from the homepage. Each file is then available at a public URL that starts with that domain, for example `https://assets.gservetech.com/brand/logo.png`.

Files are written to a folder on the server (`/data` in Docker). They are not stored in this git repository. Redeploying the app does not upload images and does not delete the ones already stored, as long as the Coolify volume stays mounted at `/data`.

Anyone who knows a file URL can view it. The admin password only protects the management actions.

## Deploy on Coolify

1. Point DNS for `assets.gservetech.com` at the VPS. Ports 80 and 443 must reach Coolify’s proxy.
2. Push this repository to Git and connect it in Coolify with build pack **Dockerfile**. Base directory `/`, Dockerfile location `/Dockerfile`.
3. Set **Ports Exposes** to `3004`. The process listens on container port 3004.
4. Set **Domains** to `https://assets.gservetech.com:3004`. The `:3004` tells Coolify which container port to use. Visitors still open `https://assets.gservetech.com` on port 443.
5. Add runtime environment variables (not build arguments). Choose the admin password in Coolify. Do not commit it.

   | Name | Value |
   | --- | --- |
   | `ADMIN_PASSWORD` | a private password of at least 8 characters |
   | `PUBLIC_BASE_URL` | `https://assets.gservetech.com` |
   | `STORAGE_DIR` | `/data` |
   | `PORT` | `3004` |

6. Open **Configuration → Persistent Storage → Add → Volume Mount**. Leave the source empty. Set the destination path to `/data`. Add this before uploading real files.
7. Deploy. Open `https://assets.gservetech.com`, sign in with the admin password, and upload a file. Use **Copy URL** or **Copy path** on that file.

If the site says “No available server”, the domain is missing `:3004` or `PORT` is not `3004`.

If uploads disappear after the next deploy, the volume is not mounted at `/data`.

## Use a file

```html
<img src="https://assets.gservetech.com/brand/logo.png" alt="Logo">
```

Browsers cache a URL for about a day. When you replace a file and need the new bytes immediately, rename it or add a query string in the page that uses it.

Allowed types: jpg, png, gif, webp, avif, svg, ico, pdf, mp4, webm, mp3, wav, ogg, woff, woff2, ttf, otf, css, js, and json. HTML is rejected. The default upload limit is 32 MB.

## Management

The homepage is the admin screen:

- **Upload** creates a file and returns its public URL.
- **Library** lists what is stored.
- **Replace** updates the bytes at the same URL.
- **Rename** moves a file to a new path. The old URL stops working.
- **Delete** removes a file.
- **Copy URL** copies `https://assets.gservetech.com/...` to the clipboard.
- **Copy path** copies the path, such as `/brand/logo.png`. Clicking the address copies the URL too.

There is no API key. Upload, replace, rename, and delete work only after you sign in with `ADMIN_PASSWORD`. Sending that password in a request header does not sign you in.

The password is not written into the Docker image or this repository. Set it in Coolify as a runtime variable. `.env` stays untracked. `.env.example` only shows the variable names.

## Local preview

```bash
npm install
npm test
npm start
```

`npm start` listens on port 3004 and stores files in `./data`, which git ignores. Set `ADMIN_PASSWORD` before starting. Docker Compose publishes the same app at `http://localhost:3004` and keeps files in a Docker volume.
