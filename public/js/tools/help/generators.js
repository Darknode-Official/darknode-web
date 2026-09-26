// Copyright (c) 2026 Darknode-Official. All rights reserved. See LICENSE.
// Plain-English help for the generators.js mini-tools. See help/README.md for the contract.
export const HELP = {
  "g-uuid-v4": {
    what: "Gives you a new random UUID each time you run it, a 36-character ID like 3f2b8c1e-9a4d-4e6f-b1c2-7d8e9f0a1b2c that is practically guaranteed to be unique. There is nothing to type.",
    when: "You need a unique ID for a database row, a test record or a file name.",
    example: {},
  },
  "g-uuid-guid": {
    what: "Gives you a new random ID in the Windows GUID style: uppercase letters wrapped in curly braces, like {3F2B8C1E-9A4D-4E6F-B1C2-7D8E9F0A1B2C}.",
    when: "You are working with Windows, the registry, .NET or Visual Studio files that expect GUIDs in this exact format.",
    example: {},
  },
  "g-uuid-nil": {
    what: "Shows the special all-zero UUID, 00000000-0000-0000-0000-000000000000, which by convention means \"no ID\" or \"empty\".",
    when: "You need a placeholder ID in test data or a config file where a real UUID is not set yet.",
    example: {},
  },
  "g-ulid": {
    what: "Gives you a new ULID, a 26-character unique ID whose first part is the current time, so IDs made later sort after IDs made earlier.",
    when: "You want unique IDs for database records or log entries that also stay in creation order when sorted alphabetically.",
    example: {},
  },
  "g-nanoid": {
    what: "Gives you a short random ID (21 characters by default) made of URL-safe letters, numbers, _ and -. You can set the length and supply your own set of characters.",
    when: "You need a compact unique ID for a short link, a file name or a record key and a full UUID is too long.",
    example: { alphabet: "", length: "21" },
  },
  "g-password": {
    what: "Gives you a strong random password. You choose the length and which kinds of characters to include (capital letters, small letters, digits, symbols), and can leave out look-alike characters such as 0 and O.",
    when: "You are creating a new account and want a password nobody can guess. Store it in a password manager, since it is not meant to be memorized.",
    example: { length: "20", upper: true, lower: true, digits: true, symbols: true, noAmbiguous: true },
  },
  "g-passphrase": {
    what: "Gives you a password made of several random short English words joined together, such as Lake-Bold-Gift-Hawk-42. You choose how many words, the separator, capital letters and an added number.",
    when: "You need a password you can actually remember and type, like for your computer login or password manager. Use at least 5 words for important accounts, since the word list is small.",
    example: { count: "5", sep: "-", capitalize: true, number: true },
  },
  "g-api-key": {
    what: "Gives you a random key that looks like a real API key: your prefix, an underscore, then random letters and numbers, such as sk_live_Ab3dE....",
    when: "You are testing an app, SDK or login flow and need realistic-looking keys. For production secrets, prefer keys created by the real service.",
    example: { prefix: "sk_test", length: "32" },
  },
  "g-hex-string": {
    what: "Gives you a random string of hex characters (0-9 and a-f). You pick how many random bytes to make; each byte becomes two characters.",
    when: "You need a random secret, salt, session token or test ID in hex form, for example a 32-byte key for a config file.",
    example: { length: "16", upper: false },
  },
  "g-random-bytes-b64": {
    what: "Gives you strong random bytes written as Base64 text, a compact way to store binary data as letters and numbers. You can choose the URL-safe version, which avoids + and / characters.",
    when: "You need a random secret such as a signing key or a session secret for an app's config file.",
    example: { length: "32", urlsafe: false },
  },
  "g-mac-address": {
    what: "Gives you a random MAC address, the hardware ID of a network card, like 02:1a:2b:3c:4d:5e. You can choose the separator and mark it as locally made so it cannot clash with a real vendor's address.",
    when: "You are setting up a virtual machine, container or test network and need a made-up hardware address.",
    example: { sep: ":", local: true },
  },
  "g-ipv4": {
    what: "Gives you a random IPv4 address (four numbers from 0 to 255, like 192.168.4.17). You can limit it to private home or office ranges.",
    when: "You need fake IP addresses for test data, logs or firewall rule examples. Without the private option it may produce a real public address, so do not scan or contact it.",
    example: { private: true },
  },
  "g-ipv6": {
    what: "Gives you a random IPv6 address, the newer and longer kind of internet address. By default it uses the 2001:db8:: range reserved for examples, and shortens runs of zeros with ::.",
    when: "You are writing documentation, tests or sample configs and need an IPv6 address that will not point at a real machine.",
    example: { docRange: true, compress: true },
  },
  "g-lorem-ipsum": {
    what: "Gives you fake Latin-looking filler text (Lorem Ipsum). You choose how many paragraphs and how many sentences each one has.",
    when: "You are designing a web page or document layout and need text to fill the space before the real words are written.",
    example: { paragraphs: "2", sentences: "4", startLorem: true },
  },
  "g-fake-name": {
    what: "Gives you a random made-up full name, such as Priya Nguyen, optionally with a middle initial.",
    when: "You need realistic-looking names for test accounts, demo screens or sample data without using real people's details.",
    example: { middle: true },
  },
  "g-fake-email": {
    what: "Gives you a random made-up email address like olivia.kim42@example.com at a test domain you pick.",
    when: "You need email addresses for sign-up tests or sample data. Choose example.com or test.local if the messages must never reach anyone.",
    example: { domain: "example.com" },
  },
  "g-fake-address": {
    what: "Gives you a random made-up US street address with a city, state and ZIP code, on two lines.",
    when: "You need a realistic-looking mailing address for test forms or demo data. The street and ZIP are random, so they may not match a real place.",
    example: {},
  },
  "g-fake-phone": {
    what: "Gives you a random made-up North American phone number in the format you choose, such as (415) 382-7719.",
    when: "You need phone numbers for test forms or sample data. The numbers are random and might belong to someone, so never call or text them.",
    example: { format: "555-555-5555" },
  },
  "g-fake-company": {
    what: "Gives you a random made-up company name such as Helix Dynamics Inc.",
    when: "You need business names for demos, mock-ups or sample customer data.",
    example: {},
  },
  "g-credit-card": {
    what: "Gives you a fake card number for the brand you choose (Visa, Mastercard, Amex or Discover) that passes the basic Luhn checksum, the math check payment forms use to catch typos.",
    when: "You are testing that a checkout form accepts correctly shaped card numbers. It is not a real card and cannot pay for anything; use your payment provider's official test numbers for real test payments.",
    example: { brand: "Visa" },
  },
  "g-totp-secret": {
    what: "Gives you a random secret in Base32 (capital letters A to Z and digits 2 to 7), the kind of setup key that two-factor authenticator apps like Google Authenticator use to create 6-digit login codes.",
    when: "You are building or testing two-factor login and need a new secret to enter into an authenticator app.",
    example: { length: "32" },
  },
  "g-hex-color": {
    what: "Gives you one random color as a hex code like #7a3fd2.",
    when: "You need a quick random color for a placeholder, a test or some design inspiration.",
    example: {},
  },
  "g-color-palette": {
    what: "Gives you five matching hex colors built around a random starting color. You choose the style: analogous (neighboring colors), complementary (opposites) or triadic (three evenly spaced colors).",
    when: "You are starting a design and want a quick set of colors that go together. Run it again for a new palette.",
    example: { scheme: "Triadic" },
  },
  "g-css-gradient": {
    what: "Gives you a ready-to-paste CSS line for a color fade (linear-gradient) with random colors, at the angle and number of colors you choose.",
    when: "You want a quick gradient background for a banner, card or button and some color ideas.",
    example: { angle: "135", stops: "3" },
  },
  "g-css-box-shadow": {
    what: "Gives you a ready-to-paste CSS box-shadow line with random position, blur, spread and darkness. You can make it an inner (inset) shadow.",
    when: "You are experimenting with shadow styles for cards or buttons and want a starting point to tweak.",
    example: { inset: false },
  },
  "g-cron": {
    what: "Pick the minute, hour, day of month, month and day of week from the lists, and get the matching five-part cron schedule line. A * means every.",
    when: "You need to schedule a script or job on a Linux server or CI system and do not remember the cron format. For patterns like every 15 minutes, edit the result by hand.",
    example: { minute: "30", hour: "2", dom: "*", month: "*", dow: "1" },
  },
  "g-gitignore": {
    what: "Pick a language (Node, Python, Java or Go) and get a starter .gitignore file, the list of files and folders Git should not track, such as build output and secret .env files.",
    when: "You are starting a new code project and do not want junk files or secrets committed to Git.",
    example: { lang: "Python" },
  },
  "g-robots-txt": {
    what: "Type the paths you want to block and allow, which crawler it applies to, and your sitemap link, and get a robots.txt file telling search engine bots which parts of your site to skip.",
    when: "You are launching a website and want to keep search engines out of admin or private pages. Polite bots follow it, but it does not actually block access.",
    example: { ua: "*", disallow: "/admin\n/private", allow: "/public", sitemap: "https://example.com/sitemap.xml" },
  },
  "g-meta-tags": {
    what: "Type a page title, description and link, and get the HTML tags that control how your page appears in search results and in link previews on social media and chat apps.",
    when: "You are publishing a web page and want a proper title and preview when someone shares the link. Add your own og:image tag if you want a preview picture.",
    example: { title: "Example Bakery", desc: "Fresh bread and pastries baked daily in Springfield.", url: "https://example.com/" },
  },
  "g-dockerfile": {
    what: "Pick a language (Node, Python, Go or Java) and get a simple starter Dockerfile, the recipe Docker uses to package your app into a container.",
    when: "You want to run your app in Docker for the first time and need a working starting point. Change file names like index.js or app.py to match your project.",
    example: { lang: "Node" },
  },
  "g-docker-compose": {
    what: "Type a service name, a Docker image and a port mapping, and get a small docker-compose.yml file that starts that container and restarts it if it stops.",
    when: "You want to quickly run a web server or other app with Docker Compose and need the basic file layout.",
    example: { service: "web", image: "nginx:latest", port: "8080:80" },
  },
  "g-nginx-conf": {
    what: "Type a domain, the folder holding your website files and a port, and get a basic Nginx server block, the config section that tells the Nginx web server how to serve that site.",
    when: "You are hosting a static website on your own Linux server with Nginx. The result has no HTTPS setup, so add that separately.",
    example: { domain: "example.com", root: "/var/www/example", port: "80" },
  },
  "g-systemd-unit": {
    what: "Type a description, the command that starts your program and the user it should run as, and get a systemd .service file that makes Linux start your program at boot and restart it if it crashes.",
    when: "You want your app or bot to keep running on a Linux server without logging in to start it by hand.",
    example: { name: "Example API", exec: "/usr/bin/node /opt/example/index.js", user: "appuser" },
  },
  "g-ssh-keygen": {
    what: "Pick a key type, add a label and output file, and get the full ssh-keygen command to paste in a terminal. It builds the command only; no key is created here.",
    when: "You need a new SSH key to log in to a server or to GitHub and want the right options without looking them up.",
    example: { type: "ed25519", comment: "you@example.com", file: "~/.ssh/id_ed25519" },
  },
  "g-openssl-cert": {
    what: "Type a name (usually a domain like localhost) and how many days it should last, and get the openssl command that creates a self-signed certificate and private key. It builds the command only.",
    when: "You need HTTPS on a local or test server. Browsers will warn about self-signed certificates, so do not use them on public sites.",
    example: { cn: "localhost", days: "365" },
  },
  "g-htpasswd": {
    what: "Type a username and password and get one line for an Apache .htpasswd file, with the password stored as an old-style SHA-1 hash (a scrambled fingerprint).",
    when: "You need simple password protection on a test folder of an Apache or Nginx site. The SHA-1 scheme is weak and unsalted, so prefer bcrypt for anything important.",
    example: { username: "demo", password: "correct-horse-battery" },
  },
  "g-pin": {
    what: "Gives you a random number PIN with the number of digits you choose (4 to 12).",
    when: "You need a new PIN for a phone, a door code, a test account or a one-time code.",
    example: { length: "6" },
  },
  "g-dice-roll": {
    what: "Choose how many dice and how many sides each has, and get each roll plus the total, like 2d6: [3, 5] total = 8.",
    when: "You are playing a board game or tabletop role-playing game and do not have dice with you.",
    example: { n: "3", m: "6" },
  },
  "g-random-int": {
    what: "Type a lowest and highest number and get one random whole number between them, including both ends.",
    when: "You need to pick a random winner, a random page or a random test value fairly.",
    example: { min: "1", max: "100" },
  },
  "g-uuid-batch": {
    what: "Choose how many and get that many random UUIDs (unique 36-character IDs), one per line.",
    when: "You are filling a test database or spreadsheet and need many unique IDs at once.",
    example: { count: "5" },
  },
  "g-placeholder-image": {
    what: "Choose a width, height and optional seed word, plus grayscale or blur, and get a picsum.photos link to a placeholder photo of that size. It only builds the link; nothing is downloaded.",
    when: "You are designing a web page and need stand-in images before real ones exist. The same seed always gives the same picture.",
    example: { width: "800", height: "400", seed: "demo", grayscale: false, blur: false },
  },
  "g-random-string": {
    what: "Gives you a random string of the length you choose, made from letters and digits, letters only, digits only, hex, or your own custom set of characters.",
    when: "You need random text for test data, a coupon code or a temporary token.",
    example: { preset: "Alphanumeric", custom: "", length: "24" },
  },
  "g-user-agent": {
    what: "Pick a browser (Chrome, Safari, Firefox or Edge) and get a realistic User-Agent string, the text a browser sends to websites to say what it is, with a random version number.",
    when: "You are testing how a website or API responds to different browsers, or need realistic values for test requests.",
    example: { browser: "Firefox" },
  },
  "g-username": {
    what: "Gives you a random username made of an adjective, a noun and some digits, like SilentFalcon42. You choose how many digits to add.",
    when: "You need usernames for test accounts, demos or a gaming profile.",
    example: { digits: "2" },
  },
};
